#pragma once
#include "fc/bruteforce.hpp"
#include <array>
#include <cstdint>

namespace fc {
// Mathematical projection of the pinned game profile's default stream only.
// A live engine may install another stream and has shared state/call ordering.
class ProfileUniformRandom final : public RandomSource {
public:
    struct Snapshot {
        std::int32_t state{};
        std::uint32_t output{};
        std::array<std::uint32_t, 32> shuffle{};
        std::uint64_t generation_calls{};
    };
    void seed(std::int32_t) noexcept;
    std::int32_t integer(std::int32_t low, std::int32_t high) override;
    // Installed default stream's RandomFloat arithmetic. One generator draw.
    float real(float low, float high);
    // Bounded default-stream RandomFloatExp projection. One generator draw;
    // helper parity excludes NaN payloads, FP status, and nondefault MXCSR.
    float real_exp(float low, float high, float exponent);
    std::uint32_t generate();
    Snapshot snapshot() const noexcept { return state_; }
private:
    static std::int32_t step(std::int32_t value) noexcept;
    Snapshot state_;
};
}
