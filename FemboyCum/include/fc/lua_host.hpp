#pragma once

#include "fc/core.hpp"
extern "C" {
#include "lua.h"
}
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace fc {

// Optional research adapter. Its fc_research Lua bridge is newly authored and
// is not a recovered historical scripting API.
class LuaJitCandidateHost final : public ScriptHost {
public:
    using Token = std::uint64_t;

    LuaJitCandidateHost() = default;
    ~LuaJitCandidateHost() override;
    LuaJitCandidateHost(const LuaJitCandidateHost&) = delete;
    LuaJitCandidateHost& operator=(const LuaJitCandidateHost&) = delete;

    // Bind once before Core::initialize(). Core must outlive active host calls.
    void bind(Core& core);
    void initialize() override;
    void event(const Event& event) override;
    void shutdown() noexcept override;

    // Executes a Lua chunk after Core::initialize(). Lua callbacks are registered
    // through fc_research.on_event and run on future Core::dispatch calls.
    void load_research_script(std::string_view source);
    std::size_t callback_count() const noexcept;
    // Fault hook for isolated tests. Counts new/growing allocations only;
    // frees and non-growing reallocations always use Lua's original allocator.
    void fail_next_allocation_for_test(std::size_t allocations_before_failure = 0) noexcept;
    void fail_allocations_for_test(std::size_t allocations_before_failure = 0) noexcept;
    int last_event_stage_for_test() const noexcept;

private:
    struct Callback { Token token; int registry_ref; };
    struct ChunkContext { const char* bytes; std::size_t length; int stage;
                          std::uint64_t event_marker{}; bool event_marker_ready{}; };
    struct EventContext { const char* name; std::size_t name_length; Token tick; int registry_ref; int stage; };
    static int initialize_trampoline(lua_State* state) noexcept;
    static int chunk_trampoline(lua_State* state) noexcept;
    static int event_trampoline(lua_State* state) noexcept;
    static int unref_trampoline(lua_State* state) noexcept;
    static int event_rollback_trampoline(lua_State* state) noexcept;
    static void* allocator_trampoline(void* userdata, void* pointer,
                                      std::size_t old_size, std::size_t new_size) noexcept;
    static int lua_on_event(lua_State* state) noexcept;
    static int lua_cancel(lua_State* state) noexcept;
    static int lua_set_text(lua_State* state) noexcept;
    bool cancel(Token token) noexcept;

    Core* core_{};
    lua_State* lua_{};
    lua_Alloc original_allocator_{};
    void* original_allocator_userdata_{};
    std::size_t fail_after_allocations_{static_cast<std::size_t>(-1)};
    bool persistent_allocation_failure_{};
    std::vector<Callback> callbacks_;
    Token next_token_{1};
    bool dispatching_{};
    int last_event_stage_{};
};

} // namespace fc
