#include "fc/lua_host.hpp"
#include "fc/lua_events.hpp"
#include "fc/lua_bit_writer_candidate.hpp"

extern "C" {
#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"
}

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>

namespace fc {
namespace {
constexpr LuaJitCandidateHost::Token max_lua_token = (std::uint64_t{1} << 53) - 1;

struct StackGuard {
    lua_State* state;
    int top;
    ~StackGuard() { if (state) lua_settop(state, top); }
};

int push_bridge_error(lua_State* state, const char* message) {
    // Call only after all local C++ objects with destructors have gone out of scope.
    // An allocation failure inside Lua may longjmp to Lua's protected caller.
    lua_pushnil(state);
    lua_pushstring(state, message);
    return 2;
}

std::string stack_error(lua_State* state, const char* prefix) {
    if (lua_type(state, -1) != LUA_TSTRING)
        return std::string(prefix) + "non-string error object";
    std::size_t length{};
    const char* detail = lua_tolstring(state, -1, &length);
    std::string result(prefix);
    result += detail ? std::string(detail, length) : std::string("missing error text");
    return result;
}

LuaJitCandidateHost* bridge_host(lua_State* state) noexcept {
    return static_cast<LuaJitCandidateHost*>(lua_touserdata(state, lua_upvalueindex(1)));
}
} // namespace

LuaJitCandidateHost::~LuaJitCandidateHost() { shutdown(); }

void LuaJitCandidateHost::fail_next_allocation_for_test(std::size_t allocations_before_failure) noexcept {
    fail_after_allocations_ = allocations_before_failure;
    persistent_allocation_failure_ = false;
}
void LuaJitCandidateHost::fail_allocations_for_test(std::size_t allocations_before_failure) noexcept {
    fail_after_allocations_ = allocations_before_failure;
    persistent_allocation_failure_ = true;
}

int LuaJitCandidateHost::last_event_stage_for_test() const noexcept { return last_event_stage_; }

void* LuaJitCandidateHost::allocator_trampoline(void* userdata, void* pointer,
                                                 std::size_t old_size, std::size_t new_size) noexcept {
    auto* host = static_cast<LuaJitCandidateHost*>(userdata);
    // Lua requires an allocator to honor frees and non-growing reallocations.
    // Fault injection applies only to a new allocation or an actual growth.
    if (new_size != 0 && (!pointer || new_size > old_size) &&
        host->fail_after_allocations_ != static_cast<std::size_t>(-1)) {
        if (host->fail_after_allocations_ == 0) {
            if (!host->persistent_allocation_failure_)
                host->fail_after_allocations_ = static_cast<std::size_t>(-1);
            return nullptr;
        }
        --host->fail_after_allocations_;
    }
    return host->original_allocator_(host->original_allocator_userdata_, pointer, old_size, new_size);
}

void LuaJitCandidateHost::bind(Core& core) {
    if (lua_) throw std::logic_error("cannot rebind active Lua host");
    core_ = &core;
}

void LuaJitCandidateHost::initialize() {
    if (!core_) throw std::logic_error("Lua host has no core binding");
    if (lua_) throw std::logic_error("Lua host already initialized");
    lua_State* state = luaL_newstate();
    if (!state) throw std::bad_alloc();
    lua_ = state;
    original_allocator_ = lua_getallocf(state, &original_allocator_userdata_);
    lua_setallocf(state, &LuaJitCandidateHost::allocator_trampoline, this);
    if (lua_cpcall(state, &LuaJitCandidateHost::initialize_trampoline, this) != 0) {
        std::string message;
        try { message = stack_error(state, "Lua initialization error: "); }
        catch (...) { shutdown(); throw; }
        shutdown();
        throw std::runtime_error(message);
    }
    lua_settop(state, 0);
}

int LuaJitCandidateHost::initialize_trampoline(lua_State* state) noexcept {
    auto* host = static_cast<LuaJitCandidateHost*>(lua_touserdata(state, 1));
    luaL_openlibs(state);
    lua_createtable(state, 0, 3);
    lua_pushlightuserdata(state, host);
    lua_pushcclosure(state, &LuaJitCandidateHost::lua_on_event, 1);
    lua_setfield(state, -2, "on_event");
    lua_pushlightuserdata(state, host);
    lua_pushcclosure(state, &LuaJitCandidateHost::lua_cancel, 1);
    lua_setfield(state, -2, "cancel");
    lua_pushlightuserdata(state, host);
    lua_pushcclosure(state, &LuaJitCandidateHost::lua_set_text, 1);
    lua_setfield(state, -2, "set_text");
    lua_setglobal(state, "fc_research");
    install_bit_writer_candidate(state);
    install_event_candidate(state);
    return 0;
}

void LuaJitCandidateHost::load_research_script(std::string_view source) {
    if (!lua_ || !core_ || !core_->active()) throw std::logic_error("Lua host is inactive");
    if (lua_gettop(lua_) != 0) throw std::logic_error("Lua stack is not idle");
    StackGuard stack{lua_, lua_gettop(lua_)};
    const Token first_new_token = next_token_;
    ChunkContext context{source.empty() ? "" : source.data(), source.size(), 1};
    if (lua_cpcall(lua_, &LuaJitCandidateHost::chunk_trampoline, &context) != 0) {
        // A failed chunk cannot leave newly registered callbacks runnable.
        for (;;) {
            int reference = LUA_NOREF;
            {
                const auto found = std::find_if(callbacks_.begin(), callbacks_.end(),
                    [first_new_token](const Callback& item) { return item.token >= first_new_token; });
                if (found == callbacks_.end()) break;
                reference = found->registry_ref;
                callbacks_.erase(found);
            }
            if (lua_cpcall(lua_, &LuaJitCandidateHost::unref_trampoline, &reference) != 0) {
                // Cleanup failure must not leave partially loaded callbacks usable.
                stack.state = nullptr;
                core_->shutdown();
                throw std::runtime_error("Lua callback cleanup failed");
            }
        }
        if (context.event_marker_ready &&
            lua_cpcall(lua_, &LuaJitCandidateHost::event_rollback_trampoline, &context.event_marker) != 0) {
            stack.state = nullptr;
            core_->shutdown();
            throw std::runtime_error("Lua candidate Event cleanup failed");
        }
        throw std::runtime_error(stack_error(lua_, context.stage == 1 ?
            "Lua compile error: " : "Lua script error: "));
    }
}

int LuaJitCandidateHost::chunk_trampoline(lua_State* state) noexcept {
    auto* context = static_cast<ChunkContext*>(lua_touserdata(state, 1));
    if (luaL_loadbuffer(state, context->bytes, context->length, "=fc_research") != 0)
        return lua_error(state);
    context->stage = 2;
    context->event_marker = event_candidate_checkpoint(state);
    context->event_marker_ready = true;
    lua_call(state, 0, 0);
    return 0;
}

int LuaJitCandidateHost::unref_trampoline(lua_State* state) noexcept {
    auto* reference = static_cast<int*>(lua_touserdata(state, 1));
    luaL_unref(state, LUA_REGISTRYINDEX, *reference);
    return 0;
}

int LuaJitCandidateHost::event_rollback_trampoline(lua_State* state) noexcept {
    const auto* marker = static_cast<std::uint64_t*>(lua_touserdata(state, 1));
    rollback_event_candidate(state, *marker);
    return 0;
}

void LuaJitCandidateHost::event(const Event& event) {
    if (!lua_) throw std::logic_error("Lua host is inactive");
    if (dispatching_) throw std::logic_error("recursive Lua event dispatch is unsupported");
    if (event.tick > max_lua_token) throw std::out_of_range("Lua event tick exceeds exact numeric range");
    if (lua_gettop(lua_) != 0) throw std::logic_error("Lua stack is not idle");
    std::vector<Token> snapshot;
    snapshot.reserve(callbacks_.size());
    for (const auto& callback : callbacks_) snapshot.push_back(callback.token);
    StackGuard stack{lua_, lua_gettop(lua_)};
    dispatching_ = true;
    struct DispatchGuard { bool& flag; ~DispatchGuard() { flag = false; } } dispatch_guard{dispatching_};
    for (const auto token : snapshot) {
        int reference = LUA_NOREF;
        {
            const auto found = std::find_if(callbacks_.begin(), callbacks_.end(),
                                            [token](const Callback& item) { return item.token == token; });
            if (found == callbacks_.end()) continue;
            reference = found->registry_ref;
        }
        EventContext context{event.name.data(), event.name.size(), event.tick, reference, 0};
        const int status = lua_cpcall(lua_, &LuaJitCandidateHost::event_trampoline, &context);
        last_event_stage_ = context.stage;
        if (status != 0)
            throw std::runtime_error(stack_error(lua_, "Lua event callback error: "));
    }
}

int LuaJitCandidateHost::event_trampoline(lua_State* state) noexcept {
    auto* context = static_cast<EventContext*>(lua_touserdata(state, 1));
    context->stage = 1;
    lua_rawgeti(state, LUA_REGISTRYINDEX, context->registry_ref);
    context->stage = 2;
    lua_pushlstring(state, context->name, context->name_length);
    context->stage = 3;
    lua_pushnumber(state, static_cast<lua_Number>(context->tick));
    context->stage = 4;
    lua_call(state, 2, 0);
    return 0;
}

void LuaJitCandidateHost::shutdown() noexcept {
    if (!lua_) return;
    lua_State* state = lua_;
    lua_ = nullptr; // Finalizers can call the bridge while lua_close runs.
    callbacks_.clear();
    lua_close(state);
    original_allocator_ = nullptr;
    original_allocator_userdata_ = nullptr;
    fail_after_allocations_ = static_cast<std::size_t>(-1);
    persistent_allocation_failure_ = false;
    dispatching_ = false;
}

std::size_t LuaJitCandidateHost::callback_count() const noexcept { return callbacks_.size(); }

bool LuaJitCandidateHost::cancel(Token token) noexcept {
    int reference = LUA_NOREF;
    {
        const auto found = std::find_if(callbacks_.begin(), callbacks_.end(),
                                        [token](const Callback& item) { return item.token == token; });
        if (found == callbacks_.end()) return false;
        reference = found->registry_ref;
        callbacks_.erase(found);
    }
    luaL_unref(lua_, LUA_REGISTRYINDEX, reference);
    return true;
}

int LuaJitCandidateHost::lua_on_event(lua_State* state) noexcept {
    LuaJitCandidateHost* host = bridge_host(state);
    if (!host || host->lua_ != state) return push_bridge_error(state, "Lua host is inactive");
    if (lua_type(state, 1) != LUA_TFUNCTION) return push_bridge_error(state, "callback must be a function");
    if (host->next_token_ > max_lua_token) return push_bridge_error(state, "Lua callback token exhausted");
    const Token token = host->next_token_;
    lua_pushnumber(state, static_cast<lua_Number>(token));
    lua_pushvalue(state, 1);
    const int reference = luaL_ref(state, LUA_REGISTRYINDEX);
    bool registered = false;
    try {
        host->callbacks_.push_back(Callback{token, reference});
        ++host->next_token_;
        registered = true;
    } catch (...) {
        // No C++ exception may cross the Lua C callback boundary.
    }
    if (!registered) {
        luaL_unref(state, LUA_REGISTRYINDEX, reference);
        return push_bridge_error(state, "could not register callback");
    }
    return 1;
}

int LuaJitCandidateHost::lua_cancel(lua_State* state) noexcept {
    LuaJitCandidateHost* host = bridge_host(state);
    if (!host || host->lua_ != state) return push_bridge_error(state, "Lua host is inactive");
    if (lua_type(state, 1) != LUA_TNUMBER) return push_bridge_error(state, "token must be a number");
    const lua_Number number = lua_tonumber(state, 1);
    if (!std::isfinite(number) || number < 1 || number > static_cast<lua_Number>(max_lua_token) ||
        std::floor(number) != number)
        return push_bridge_error(state, "token must be a positive integer");
    const bool removed = host->cancel(static_cast<Token>(number));
    lua_pushboolean(state, removed ? 1 : 0);
    return 1;
}

int LuaJitCandidateHost::lua_set_text(lua_State* state) noexcept {
    LuaJitCandidateHost* host = bridge_host(state);
    if (!host || host->lua_ != state || !host->core_) return push_bridge_error(state, "Lua host is inactive");
    if (lua_type(state, 1) != LUA_TSTRING) return push_bridge_error(state, "text must be a string");
    std::size_t length{};
    const char* bytes = lua_tolstring(state, 1, &length);
    lua_pushboolean(state, 1); // Reserve the success result before changing Core state.
    char failure[256]{};
    bool succeeded = false;
    try {
        std::string value(bytes, length);
        host->core_->set_text(std::move(value));
        succeeded = true;
    } catch (const std::exception& error) {
        std::snprintf(failure, sizeof(failure), "set_text rejected: %.220s", error.what());
    } catch (...) {
        std::snprintf(failure, sizeof(failure), "set_text rejected");
    }
    if (!succeeded) {
        lua_pop(state, 1);
        return push_bridge_error(state, failure);
    }
    return 1;
}

} // namespace fc
