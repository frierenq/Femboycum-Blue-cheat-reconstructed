#pragma once
#include <array>
#include <cstdint>
#include <optional>

// Analyst-authored reconstruction of the ORIGINAL selector block
// 0x4134af6d..0x4134b03d. No assumed/deobfuscated export is its source.
// This is a slice, not the entire 0x4134ab40 function or an engine ABI.
namespace femboylose::recovered {
using SequenceCaches=std::array<std::array<std::int32_t,4>,5>;
struct SequenceChoice {
    std::int32_t sequence;
    std::uint32_t cache_address;
    unsigned variant;
};
inline std::optional<SequenceChoice> select_cached_sequence(
    std::int32_t selector,float anim_duck_amount,float crouch_speed_portion,
    const SequenceCaches& caches){
    constexpr std::array<std::uint32_t,5> bases{
        0x4223f430u,0x4223f418u,0x4223f2f8u,0x4223f370u,0x4223f380u};
    const std::uint32_t row=static_cast<std::uint32_t>(selector)-985u;
    if(row>4u)return std::nullopt;
    // UCOMISS+CMOVBE selects the low side for equality or unordered input.
    // Quiet NaN therefore follows the same choice as the low side.
    const unsigned variant=(anim_duck_amount>0.55f?2u:0u)
                           +(crouch_speed_portion>0.25f?1u:0u);
    const std::int32_t sequence=caches[row][variant];
    if(sequence<=0)return std::nullopt;
    return SequenceChoice{sequence,bases[row]+4u*variant,variant};
}
}
