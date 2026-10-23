#include "fc/lua_bit_writer_candidate.hpp"
#include "fc/bit_writer.hpp"
#include "fc/voice_message.hpp"

extern "C" {
#include "lauxlib.h"
}

#include <cmath>
#include <cstdint>
#include <limits>
#include <new>
#include <span>
#include <type_traits>

namespace fc {
namespace {
constexpr char metatable_name[] = "fc.research.BitWriter20";
constexpr std::uint32_t live_magic = 0x42573230u;

struct WriterUserdata {
    std::uint32_t magic{};
    ResearchBitWriter20 writer{};
};
static_assert(std::is_nothrow_default_constructible_v<WriterUserdata>);
static_assert(std::is_trivially_destructible_v<WriterUserdata>);
static_assert(std::is_trivially_destructible_v<BitWriter20Snapshot>);
static_assert(std::is_trivially_destructible_v<VoiceMessage20WireBody>);
static_assert(std::is_trivially_destructible_v<VoiceMessage20WireFrame>);
static_assert(VoiceMessage20WireFrame::max_size == 36);

// These Lua C functions retain only trivially destructible locals across Lua
// API calls. Lua allocation/error paths may longjmp to the host's cpcall.
WriterUserdata* checked(lua_State* state) {
    auto* object = static_cast<WriterUserdata*>(luaL_checkudata(state, 1, metatable_name));
    if (lua_objlen(state, 1) != sizeof(WriterUserdata) || object->magic != live_magic)
        luaL_error(state, "invalid or finalized research bit writer");
    return object;
}

int make_writer(lua_State* state) noexcept {
    if (lua_gettop(state) != 0)
        return luaL_error(state, "new_bit_writer20 takes no arguments");
    void* storage = lua_newuserdata(state, sizeof(WriterUserdata));
    auto* object = new (storage) WriterUserdata{};
    object->magic = live_magic;
    luaL_getmetatable(state, metatable_name);
    lua_setmetatable(state, -2);
    return 1;
}

int collect_writer(lua_State* state) noexcept {
    auto* object = static_cast<WriterUserdata*>(lua_touserdata(state, 1));
    if (object && lua_objlen(state, 1) == sizeof(WriterUserdata) && object->magic == live_magic) {
        object->magic = 0;
        object->writer.~ResearchBitWriter20();
    }
    return 0;
}

int write_bits(lua_State* state) noexcept {
    auto* object = checked(state);
    if (lua_type(state, 2) != LUA_TNUMBER || lua_type(state, 3) != LUA_TNUMBER)
        return luaL_error(state, "write_bits requires numeric value and count");
    const lua_Number value = lua_tonumber(state, 2);
    const lua_Number count = lua_tonumber(state, 3);
    if (!std::isfinite(value) || !std::isfinite(count) ||
        value < 0 || value > static_cast<lua_Number>(std::numeric_limits<std::uint32_t>::max()) ||
        count < 1 || count > 32 || std::floor(value) != value || std::floor(count) != count)
        return luaL_error(state, "write_bits requires a fitting uint32 value and 1..32 count");
    const auto bits = static_cast<unsigned>(count);
    const auto word = static_cast<std::uint32_t>(value);
    if (bits < 32 && (word >> bits) != 0)
        return luaL_error(state, "write_bits value exceeds count width");
    const char* failure = nullptr;
    try { object->writer.write_bits(word, bits); }
    catch (...) { failure = "write_bits failed"; }
    if (failure) return luaL_error(state, "%s", failure);
    return 0;
}

int write_coord(lua_State* state) noexcept {
    auto* object = checked(state);
    if (lua_type(state, 2) != LUA_TNUMBER)
        return luaL_error(state, "write_coord requires a number");
    const lua_Number number = lua_tonumber(state, 2);
    if (!std::isfinite(number) || std::fabs(number) >= 16385.0)
        return luaL_error(state, "write_coord requires a finite bounded number");
    const float value = static_cast<float>(number);
    if (!std::isfinite(value) || std::fabs(value) >= 16385.0f)
        return luaL_error(state, "write_coord requires a finite bounded number");
    const char* failure = nullptr;
    try { object->writer.write_coord(value); }
    catch (...) { failure = "write_coord failed"; }
    if (failure) return luaL_error(state, "%s", failure);
    return 0;
}

int crypt(lua_State* state) noexcept {
    auto* object = checked(state);
    if (lua_type(state, 2) != LUA_TSTRING)
        return luaL_error(state, "crypt requires a string key");
    std::size_t length{};
    const char* bytes = lua_tolstring(state, 2, &length);
    if (length > static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max()))
        return luaL_error(state, "crypt key exceeds bounded length");
    const char* failure = nullptr;
    try {
        object->writer.crypt(std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(bytes), length));
    } catch (...) { failure = "crypt failed"; }
    if (failure) return luaL_error(state, "%s", failure);
    return 0;
}

int is_overflowed(lua_State* state) noexcept {
    auto* object = checked(state);
    lua_pushboolean(state, object->writer.is_overflowed() ? 1 : 0);
    return 1;
}

int snapshot(lua_State* state) noexcept {
    auto* object = checked(state);
    const BitWriter20Snapshot value = object->writer.snapshot();
    lua_createtable(state, 0, 3);
    lua_pushlstring(state, reinterpret_cast<const char*>(value.data.data()), value.data.size());
    lua_setfield(state, -2, "data");
    lua_pushnumber(state, static_cast<lua_Number>(value.bit_cursor));
    lua_setfield(state, -2, "bit_cursor");
    lua_pushboolean(state, value.overflow ? 1 : 0);
    lua_setfield(state, -2, "overflow");
    return 1;
}

int voice_message_body(lua_State* state) noexcept {
    auto* object = checked(state);
    if (lua_gettop(state) != 1)
        return luaL_error(state, "voice_message_body requires one research writer");
    const auto value = object->writer.snapshot();
    if (value.overflow)
        return luaL_error(state, "overflowed research writer has no applicable voice message body");
    const auto body = serialize_voice_message20(value.data);
    lua_pushlstring(state, reinterpret_cast<const char*>(body.bytes.data()), body.size);
    return 1;
}

int voice_message_frame(lua_State* state) noexcept {
    auto* object = checked(state);
    if (lua_gettop(state) != 1)
        return luaL_error(state, "voice_message_frame requires one research writer");
    const auto value = object->writer.snapshot();
    if (value.overflow)
        return luaL_error(state, "overflowed research writer has no applicable voice message frame");
    const auto frame = serialize_voice_message20_frame(value.data);
    lua_pushlstring(state, reinterpret_cast<const char*>(frame.bytes.data()), frame.size);
    return 1;
}

void method(lua_State* state, const char* name, lua_CFunction function) {
    lua_pushcfunction(state, function);
    lua_setfield(state, -2, name);
}
} // namespace

void install_bit_writer_candidate(lua_State* state) noexcept {
    const int top = lua_gettop(state);
    if (luaL_newmetatable(state, metatable_name)) {
        method(state, "write_bits", &write_bits);
        method(state, "write_coord", &write_coord);
        method(state, "crypt", &crypt);
        method(state, "is_overflowed", &is_overflowed);
        method(state, "snapshot", &snapshot);
        method(state, "__gc", &collect_writer);
        lua_pushvalue(state, -1);
        lua_setfield(state, -2, "__index");
    }
    lua_pop(state, 1);
    lua_getglobal(state, "fc_research");
    if (lua_type(state, -1) != LUA_TTABLE) {
        luaL_error(state, "fc_research is unavailable for bit writer installation");
        return;
    }
    method(state, "new_bit_writer20", &make_writer);
    method(state, "voice_message_body", &voice_message_body);
    method(state, "voice_message_frame", &voice_message_frame);
    lua_settop(state, top);
}

} // namespace fc
