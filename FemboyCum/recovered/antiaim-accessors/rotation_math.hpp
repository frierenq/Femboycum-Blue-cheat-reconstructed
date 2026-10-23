#pragma once
#include <cmath>
#include <cstdint>
#include <cstring>

// Analyst-authored numeric transformation from original 0x41958980.
// It takes a value instead of reading original global 0x424f46b8.
// Ordinary masked FP environment only; original CRT/FPU state ABI is excluded.
namespace femboylose::recovered {
inline int classify_rotation_input(float value){
    std::uint32_t bits;std::memcpy(&bits,&value,sizeof(bits));
    const auto magnitude=bits&0x7fffffffu;
    const auto exponent=bits&0x7f800000u;
    if(exponent==0x7f800000u)return (bits&0x7fffffu)?2:1;
    if(magnitude==0)return 0;
    return exponent? -1:-2;
}
inline float normalize_rotation_pass(float input){
    const auto classification=classify_rotation_input(input);
    const float sanitized=(classification==1 || classification==2)?0.0f:input;
    float result=static_cast<float>(std::fmod(static_cast<double>(sanitized),360.0));
    if(result>180.0f)result+=-360.0f;
    if(result< -180.0f)result+=360.0f;
    return result;
}
inline float normalized_rotation(float stored_rotation){
    // The original accessor performs both passes, even where idempotent.
    return normalize_rotation_pass(normalize_rotation_pass(stored_rotation));
}
}
