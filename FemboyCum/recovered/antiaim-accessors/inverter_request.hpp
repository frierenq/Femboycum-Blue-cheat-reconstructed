#pragma once
#include "api_overloads.hpp"
#include <cmath>

// Analyst-authored semantic slices. These are not the original source or a
// replacement for the enclosing update method. No native addresses are called.
namespace femboylose::recovered {
inline std::optional<float> matching_inverter_request_block(
    const InverterRequestState& context,std::uint32_t current_counter){
    // 0x41360e34..0x41360e75. A mismatch leaves this block for other decisions;
    // it does not imply a zero result, rejected request, or unchanged active bit.
    if(context.request_counter!=current_counter)return std::nullopt;
    return context.request_value? -60.0f:60.0f;
    // No request field or active byte is written by the matching branch.
}
inline std::uint8_t inverter_active_from_result_block(float decision_result){
    // 0x41368fa6..0x41368fb4: UCOMISS result,0; SETB. An unordered
    // comparison also sets CF. Floating-point exceptions are not reproduced.
    return static_cast<std::uint8_t>(std::isnan(decision_result)||decision_result<0.0f);
}
}
