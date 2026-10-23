#pragma once

extern "C" {
#include "lua.h"
}

namespace fc {

// Call only inside a protected Lua boundary after the host has installed
// fc_research. Installs a newly authored, owned 20-byte writer factory.
void install_bit_writer_candidate(lua_State* state) noexcept;

} // namespace fc
