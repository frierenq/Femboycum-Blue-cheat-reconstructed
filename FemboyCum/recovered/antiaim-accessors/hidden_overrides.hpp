#pragma once
#include "rotation_math.hpp"
#include <cstdint>
#include <optional>

// Analyst-authored local setter/consumer/reset slices. Reaching each original
// consumer block is a precondition; no full game update/event ABI is modeled.
namespace femboylose::recovered {
struct HiddenOverrideState {
    float yaw=0;std::uint8_t yaw_enabled=0;     // Native +0x80/+0x84.
    float pitch=0;std::uint8_t pitch_enabled=0; // Native +0x88/+0x8c.
    std::uint8_t flag_6c=0,flag_74=0,flag_7c=0,flag_90=0;
};
inline void request_hidden_yaw(HiddenOverrideState& state,float value){state.yaw=value;state.yaw_enabled=1;}
inline void request_hidden_pitch(HiddenOverrideState& state,float value){state.pitch=value;state.pitch_enabled=1;}
inline std::optional<float> consume_hidden_yaw_block(HiddenOverrideState& state){
    if(state.yaw_enabled==0)return std::nullopt;
    const float copied=state.yaw;
    state.yaw_enabled=0;
    return copied; // Original copy/flag-clear precedes later yaw processing.
}
inline bool consume_hidden_pitch_block(HiddenOverrideState& state,float& destination){
    if(state.pitch_enabled==0)return false;
    const float result=normalize_rotation_pass(state.pitch);
    destination=result;
    state.pitch_enabled=0;
    return true;
}
inline void reset_override_flags_block(HiddenOverrideState& state,std::uint32_t counter_4d30){
    if(counter_4d30!=0)return;
    state.pitch_enabled=0;state.yaw_enabled=0;
    state.flag_6c=0;state.flag_74=0;state.flag_7c=0;state.flag_90=0;
}
}
