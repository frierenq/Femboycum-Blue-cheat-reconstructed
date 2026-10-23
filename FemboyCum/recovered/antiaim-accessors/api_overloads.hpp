#pragma once
#include "rotation_math.hpp"
#include <array>
#include <cstdint>
#include <optional>

// Analyst-authored slices only: dispatch metadata, request writes and scalar
// rotation selection. Returned addresses are identifiers and are never called.
namespace femboylose::recovered {
enum class AntiaimMethod:unsigned {Inverter,Rotation,Target};
inline std::optional<std::uint32_t> select_antiaim_overload(
    AntiaimMethod method,bool validated_leading_object,unsigned argument_count,int second_lua_type){
    constexpr std::array<std::array<std::uint32_t,2>,3> functions{{
        {{0x41a2d810u,0x419f4f40u}},{{0x41958980u,0x4199b590u}},{{0x419c8400u,0x419d41d0u}}
    }};
    if(!validated_leading_object)return std::nullopt;
    const auto row=static_cast<unsigned>(method);
    // Counts include the validated leading Lua object. Type 1 is Boolean.
    if(argument_count==1)return functions[row][0];
    if(argument_count==2 && second_lua_type==1)return functions[row][1];
    return std::nullopt;
}
struct InverterRequestState {
    std::uint8_t active;          // Native context +0x2b5; getter reads this.
    std::uint32_t request_counter;// +0x40; setter writes this.
    std::uint8_t request_value;   // +0x44; setter writes this.
};
inline void record_inverter_request(InverterRequestState& context,std::uint8_t desired,
    std::uint8_t use_cached_counter,std::uint32_t cached_counter,
    std::uint32_t counter_4d2c,std::uint32_t counter_4d30){
    context.request_counter=use_cached_counter?cached_counter:counter_4d2c+counter_4d30+1u;
    context.request_value=desired;
    // The native setter does not write the separately-read active byte.
}
inline float rotation_boolean_form(std::uint8_t choose_alternate,float stored_default,float stored_alternate){
    // Original one-Boolean native function uses one normalization pass.
    return normalize_rotation_pass(choose_alternate?stored_alternate:stored_default);
}
}
