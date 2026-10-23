#pragma once
#include <cstdint>
#include <string_view>

// Analyst-authored names from the supplied English catalog and checked native
// constructor/option-order joins. These are not recovered original C++ symbols.
namespace femboylose::recovered {
enum class BodyYawOption:std::uint32_t {
    AvoidOverlap=1u,Jitter=2u,RandomizeJitter=4u,AntiBruteforce=8u
};
enum class BodyYawFreestandingMode:std::int32_t {Off=0,PeekFake=1,PeekReal=2};
constexpr std::uint32_t option_bit(BodyYawOption option){return static_cast<std::uint32_t>(option);}
constexpr std::uint32_t localization_key(std::string_view bytes){
    // Original 0x41b99ef3..0x41b99fa5: seed 5381, signed bytes, modulo 2^32.
    std::uint32_t hash=5381u;
    for(const char character:bytes){
        const auto byte=static_cast<unsigned char>(character);
        const auto signed_byte=byte<128u?static_cast<int>(byte):static_cast<int>(byte)-256;
        hash=hash*33u+static_cast<std::uint32_t>(signed_byte);
    }
    return hash;
}
}
