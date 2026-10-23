#pragma once
#include <cstdint>
#include <cstring>
#include <xmmintrin.h>

// Analyst-authored numeric projection of original 0x415738f0. The conversion
// uses the native SSE instruction rather than a C++ out-of-range integer cast.
// Ordinary round-to-nearest, masked-exception environment; no original ABI.
namespace femboylose::recovered {
inline float turn16_constant(std::uint32_t bits){
    float value;std::memcpy(&value,&bits,sizeof(value));return value;
}
inline std::uint16_t turn16_code(float input){
    const auto scaled=_mm_mul_ss(_mm_set_ss(input),_mm_set_ss(turn16_constant(0x43360b61u)));
    const auto converted=static_cast<std::uint32_t>(_mm_cvttss_si32(scaled));
    return static_cast<std::uint16_t>(converted&0xffffu);
}
inline float quantize_turn16(float input){
    const auto code=static_cast<int>(turn16_code(input));
    const auto unpacked=_mm_cvtsi32_ss(_mm_setzero_ps(),code);
    return _mm_cvtss_f32(_mm_mul_ss(unpacked,_mm_set_ss(turn16_constant(0x3bb40000u))));
}
}
