#include "fc/lua_events.hpp"
extern "C" {
#include "lauxlib.h"
}
#include <bit>
#include <cstdint>
#include <cstring>
#include <limits>

namespace fc {
namespace {
constexpr char metatable_name[] = "fc.candidate.Event";
constexpr std::uint64_t max_entry = (std::uint64_t{1} << 53) - 1;
char map_registry_key;
struct Name { std::uint32_t hash; std::uint32_t length; };

// Every Lua C frame in this file has only trivial locals. Allocation/error
// nonlocal exits therefore do not skip C++ objects requiring destruction.
Name* event_name(lua_State* state) {
    auto* name = static_cast<Name*>(luaL_checkudata(state, 1, metatable_name));
    const auto bytes = lua_objlen(state, 1);
    if (bytes < sizeof(Name) || name->length > bytes - sizeof(Name))
        luaL_error(state, "invalid candidate Event storage");
    return name;
}

int vector_for(lua_State* state, std::uint32_t hash, bool create) {
    lua_pushnumber(state, static_cast<lua_Number>(hash));
    lua_rawget(state, lua_upvalueindex(1));
    if (lua_isnil(state, -1) && create) {
        lua_pop(state, 1);
        lua_newtable(state);
        lua_pushnumber(state, static_cast<lua_Number>(hash));
        lua_pushvalue(state, -2);
        lua_rawset(state, lua_upvalueindex(1));
    }
    return lua_gettop(state);
}

void function_argument(lua_State* state) {
    if (lua_type(state, 2) != LUA_TFUNCTION)
        luaL_error(state, "bad argument #1 (function expected)");
}

// Entry [1] owns the function, [2] marks active registration, [3] is its ID. Snapshots
// retain entries, while a remove/re-add makes a distinct entry for next call.
int find_function(lua_State* state, int vector, int count) {
    for (int index = 1; index <= count; ++index) {
        lua_rawgeti(state, vector, index);
        lua_rawgeti(state, -1, 1);
        const bool equal = lua_rawequal(state, -1, 2) != 0;
        lua_pop(state, 2);
        if (equal) return index;
    }
    return 0;
}

int callback_count(lua_State* state, int vector) {
    const auto count = lua_objlen(state, vector);
    if (count >= static_cast<std::size_t>(std::numeric_limits<int>::max()))
        luaL_error(state, "candidate Event callback capacity exceeded");
    return static_cast<int>(count);
}

void erase_function(lua_State* state, int vector, int index, int count) {
    lua_rawgeti(state, vector, index);
    lua_pushboolean(state, 0);
    lua_rawseti(state, -2, 2);
    lua_pop(state, 1);
    for (int current = index; current < count; ++current) {
        lua_rawgeti(state, vector, current + 1);
        lua_rawseti(state, vector, current);
    }
    lua_pushnil(state);
    lua_rawseti(state, vector, count);
}

int edit(lua_State* state, int mode) {
    const auto* name = event_name(state);
    function_argument(state);
    const int vector = vector_for(state, name->hash, mode != 0);
    if (lua_isnil(state, vector)) return 0;
    const int count = callback_count(state, vector);
    const int index = find_function(state, vector, count);
    if (index != 0) {
        if (mode != 1) erase_function(state, vector, index, count);
    } else if (mode != 0) {
        lua_getfield(state, lua_upvalueindex(1), "next_entry");
        const auto token = static_cast<std::uint64_t>(lua_tonumber(state, -1));
        lua_pop(state, 1);
        if (token > max_entry) return luaL_error(state, "candidate Event registration IDs exhausted");
        // Reserve the ID before publishing an entry; failed allocation leaves a gap.
        lua_pushnumber(state, static_cast<lua_Number>(token + 1));
        lua_setfield(state, lua_upvalueindex(1), "next_entry");
        lua_createtable(state, 3, 0);
        lua_pushvalue(state, 2);
        lua_rawseti(state, -2, 1);
        lua_pushboolean(state, 1);
        lua_rawseti(state, -2, 2);
        lua_pushnumber(state, static_cast<lua_Number>(token));
        lua_rawseti(state, -2, 3);
        lua_rawseti(state, vector, count + 1);
    }
    return 0;
}
int set(lua_State* state) { return edit(state, 1); }
int unset(lua_State* state) { return edit(state, 0); }

int callable(lua_State* state) {
    const auto* name = event_name(state);
    const int arguments = lua_gettop(state);
    if (arguments == 1) {
        const int vector = vector_for(state, name->hash, false);
        lua_pushinteger(state, lua_isnil(state, vector) ? 0 : callback_count(state, vector));
        return 1;
    }
    if (arguments == 2) return edit(state, 2);
    if (arguments == 3) {
        if (lua_type(state, 3) != LUA_TBOOLEAN)
            return luaL_error(state, "candidate Event explicit toggle requires a boolean");
        return edit(state, lua_toboolean(state, 3) ? 1 : 0);
    }
    return luaL_error(state, "unsupported candidate Event callable argument count");
}

bool manual_skip(std::uint32_t hash) noexcept {
    constexpr std::uint32_t hashes[] = {
        0x987aff41u, 0x9c62a07fu, 0xb1db03abu, 0xd3793758u, 0xd7e8e984u,
        0xdc09e123u, 0xfc460361u, 0x03b7c8c4u, 0x087391cau, 0x16422f92u,
        0x192ccfe5u, 0x1a0e622eu, 0x1bf01450u, 0x2b687d4au, 0x2ecdb4b7u,
        0x3647f691u, 0x76c9fe3bu
    };
    for (const auto value : hashes) if (hash == value) return true;
    return false;
}

int call(lua_State* state) {
    const auto* name = event_name(state);
    const int arguments = lua_gettop(state);
    if (manual_skip(name->hash)) return 0;
    if (name->hash == 0xdb78e17fu)
        return luaL_error(state, "special native Event call path is not reconstructed");
    const int vector = vector_for(state, name->hash, false);
    if (lua_isnil(state, vector)) return 0;
    const int count = callback_count(state, vector);
    lua_createtable(state, count, 0);
    const int snapshot = lua_gettop(state);
    for (int index = 1; index <= count; ++index) {
        lua_rawgeti(state, vector, index);
        lua_rawseti(state, snapshot, index);
    }
    for (int index = 1; index <= count; ++index) {
        lua_rawgeti(state, snapshot, index);
        const int entry = lua_gettop(state);
        lua_rawgeti(state, entry, 2);
        const bool active = lua_toboolean(state, -1) != 0;
        lua_pop(state, 1);
        if (active) {
            if (!lua_checkstack(state, arguments + 2))
                return luaL_error(state, "candidate Event argument stack exhausted");
            lua_rawgeti(state, entry, 1);
            for (int argument = 2; argument <= arguments; ++argument)
                lua_pushvalue(state, argument);
            if (lua_pcall(state, arguments - 1, 0, 0) != 0) return lua_error(state);
        }
        lua_pop(state, 1);
    }
    return 0;
}

int lookup(lua_State* state) {
    const int receiver_type = lua_type(state, 1);
    if (receiver_type != LUA_TTABLE && receiver_type != LUA_TUSERDATA)
        return luaL_error(state, "value is not a table or a userdata that can behave like one");
    if (lua_type(state, 2) != LUA_TSTRING)
        return luaL_error(state, "candidate Event lookup requires a string key");
    std::size_t length{};
    const char* bytes = lua_tolstring(state, 2, &length);
    if (length > std::numeric_limits<std::size_t>::max() - sizeof(Name) ||
        length > std::numeric_limits<std::uint32_t>::max())
        return luaL_error(state, "candidate Event name exceeds capacity");
    auto* name = static_cast<Name*>(lua_newuserdata(state, sizeof(Name) + length));
    name->hash = 0x1505u;
    name->length = static_cast<std::uint32_t>(length);
    std::memcpy(name + 1, bytes, length);
    for (std::size_t index = 0; index < length; ++index) {
        const auto byte = static_cast<std::uint8_t>(bytes[index]);
        const auto signed_byte = std::bit_cast<std::int8_t>(byte);
        name->hash = name->hash * 33u + static_cast<std::uint32_t>(static_cast<std::int32_t>(signed_byte));
    }
    luaL_getmetatable(state, metatable_name);
    lua_setmetatable(state, -2);
    return 1;
}

void method(lua_State* state, int map, const char* name, lua_CFunction function) {
    lua_pushvalue(state, map);
    lua_pushcclosure(state, function, 1);
    lua_setfield(state, -2, name);
}
}

void install_event_candidate(lua_State* state) noexcept {
    const int top = lua_gettop(state);
    lua_newtable(state);
    const int map = lua_gettop(state);
    lua_pushnumber(state, 1);
    lua_setfield(state, map, "next_entry");
    lua_pushlightuserdata(state, &map_registry_key);
    lua_pushvalue(state, map);
    lua_rawset(state, LUA_REGISTRYINDEX);
    luaL_newmetatable(state, metatable_name);
    const int metatable = lua_gettop(state);
    lua_newtable(state);
    method(state, map, "set", &set);
    method(state, map, "unset", &unset);
    method(state, map, "call", &call);
    lua_setfield(state, metatable, "__index");
    method(state, map, "__call", &callable);
    lua_newtable(state);
    lua_newtable(state);
    lua_pushcfunction(state, &lookup);
    lua_setfield(state, -2, "__index");
    lua_setmetatable(state, -2);
    lua_setglobal(state, "events");
    lua_settop(state, top);
}

std::uint64_t event_candidate_checkpoint(lua_State* state) noexcept {
    lua_pushlightuserdata(state, &map_registry_key);
    lua_rawget(state, LUA_REGISTRYINDEX);
    lua_getfield(state, -1, "next_entry");
    const auto token = static_cast<std::uint64_t>(lua_tonumber(state, -1));
    lua_pop(state, 2);
    return token;
}

void rollback_event_candidate(lua_State* state, std::uint64_t first_new) noexcept {
    lua_pushlightuserdata(state, &map_registry_key);
    lua_rawget(state, LUA_REGISTRYINDEX);
    const int map = lua_gettop(state);
    lua_pushnil(state);
    while (lua_next(state, map) != 0) {
        if (lua_istable(state, -1)) {
            const int vector = lua_gettop(state);
            int count = callback_count(state, vector);
            for (int index = count; index > 0; --index) {
                lua_rawgeti(state, vector, index);
                lua_rawgeti(state, -1, 3);
                const auto token = static_cast<std::uint64_t>(lua_tonumber(state, -1));
                lua_pop(state, 2);
                if (token >= first_new) erase_function(state, vector, index, count--);
            }
        }
        lua_pop(state, 1);
    }
    lua_pop(state, 1);
}
}
