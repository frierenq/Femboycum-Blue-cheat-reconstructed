#pragma once
#include <cmath>
#include <cstdint>
#include <cstring>
#include <xmmintrin.h>

// Analyst-authored reconstruction of the complete original 0x41b707e0 leaf.
// No original target code, game pointer or engine callback is invoked.
// Explicit scalar SSE preserves operation order and MAXSS/MINSS operand order.
namespace femboylose::recovered {
inline float binary32(std::uint32_t bits){
    float value;std::memcpy(&value,&bits,sizeof(value));return value;
}
struct DesyncInputs {
    float walk_run_transition;             // Native state +0x11c.
    float walk_speed_portion;              // +0xf8.
    float crouch_speed_portion;            // +0xfc.
    float anim_duck_amount;                // +0xa4.
    float aim_yaw_max;                     // +0x338.
};
inline float maximum_desync_math(const DesyncInputs& state){
    const auto zero=_mm_setzero_ps();
    const auto one=_mm_set_ss(1.0f);
    auto transition=_mm_mul_ss(_mm_set_ss(state.walk_run_transition),
                              _mm_set_ss(binary32(0xbe99999au)));
    const auto duck=_mm_set_ss(state.anim_duck_amount);
    auto walk=_mm_max_ss(_mm_set_ss(state.walk_speed_portion),zero);
    walk=_mm_min_ss(walk,one);
    // Original bits are 0xbe4ccccc, not the usual -0.2f literal's 0xbe4ccccd.
    transition=_mm_add_ss(transition,_mm_set_ss(binary32(0xbe4cccccu)));
    const auto mixed=_mm_mul_ss(transition,walk);
    auto modifier=_mm_add_ss(one,mixed);
    // UCOMISS 0,duck + JAE skips ordered duck<=0; unordered enters this block.
    if(!(state.anim_duck_amount<=0.0f)){
        auto crouch=_mm_max_ss(zero,_mm_set_ss(state.crouch_speed_portion));
        crouch=_mm_min_ss(crouch,one);
        const auto remaining=_mm_sub_ss(_mm_set_ss(-0.5f),mixed);
        auto adjustment=_mm_mul_ss(duck,crouch);
        adjustment=_mm_mul_ss(adjustment,remaining);
        modifier=_mm_add_ss(modifier,adjustment);
    }
    return _mm_cvtss_f32(_mm_mul_ss(modifier,_mm_set_ss(state.aim_yaw_max)));
}
}
