#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <utility>

// Analyst-authored semantic reconstruction from original 0x4134bd70 blocks.
// The caller supplies a test lookup. This does not call or implement the
// original engine callback, TLS initialization, guards, allocation ABI or SEH.
namespace femboylose::recovered {
struct SequenceCacheDefinition {
    std::int32_t selector;
    std::uint32_t address;
    const char* base_name;
};
inline constexpr std::array<SequenceCacheDefinition,5> sequence_cache_definitions{{
    {985,0x4223f430u,"jump"},
    {986,0x4223f418u,"fall"},
    {987,0x4223f2f8u,"ladder_climb"},
    {988,0x4223f370u,"land_light"},
    {989,0x4223f380u,"land_heavy"}
}};

template<class Lookup>
std::array<std::int32_t,4> build_sequence_cache(const char* base_name,Lookup&& lookup){
    const std::string base(base_name);
    std::array<std::int32_t,4> ids{};
    ids[0]=lookup(base);
    ids[2]=lookup(base+"_crouch");
    ids[1]=lookup(base+"_moving");
    ids[3]=lookup(base+"_crouch_moving");
    // Original fallback checks compare exactly -1, not <=0.
    if(ids[2]==-1)ids[2]=ids[0];
    if(ids[1]==-1)ids[1]=ids[0];
    if(ids[3]==-1){
        ids[3]=lookup(base+"_moving_crouch");
        if(ids[3]==-1)ids[3]=ids[1];
        if(ids[3]==-1)ids[3]=ids[2];
        if(ids[3]==-1)ids[3]=ids[0];
    }
    return ids;
}
}
