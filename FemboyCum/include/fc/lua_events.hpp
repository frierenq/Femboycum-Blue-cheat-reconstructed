#pragma once
extern "C" {
#include "lua.h"
}
#include <cstdint>
namespace fc {
// Call only within a protected Lua boundary. Installs a bounded reconstructed
// Event namespace in the optional candidate, not a complete historical Lua API.
void install_event_candidate(lua_State* state) noexcept;
// Protected-call-only lifecycle helpers. Rollback removes new registrations,
// preserving earlier successful cancellations and other script side effects.
std::uint64_t event_candidate_checkpoint(lua_State* state) noexcept;
void rollback_event_candidate(lua_State* state, std::uint64_t first_new) noexcept;
}
