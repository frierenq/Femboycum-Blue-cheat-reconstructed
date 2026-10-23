#include "fc/uniform_random.hpp"
#include <bit>
#include <cstdint>
#include <emmintrin.h>
#include <stdexcept>

namespace fc {
void ProfileUniformRandom::seed(std::int32_t value) noexcept {
    const auto word = std::bit_cast<std::uint32_t>(value);
    const auto magnitude = value < 0 ? 0u - word : word;
    state_.state = std::bit_cast<std::int32_t>(0u - magnitude);
    state_.output = 0;
}
std::int32_t ProfileUniformRandom::step(std::int32_t value) noexcept {
    const auto quotient = value / 127773;
    auto next = 16807 * (value - quotient * 127773) - 2836 * quotient;
    if (next < 0) next += 2147483647;
    return next;
}
std::uint32_t ProfileUniformRandom::generate() {
    ++state_.generation_calls;
    if (state_.state <= 0 || state_.output == 0) {
        auto candidate = std::bit_cast<std::int32_t>(0u - std::bit_cast<std::uint32_t>(state_.state));
        if (candidate < 1) candidate = 1;
        state_.state = candidate;
        for (int slot = 39; slot >= 0; --slot) {
            state_.state = step(state_.state);
            if (slot < 32) state_.shuffle[static_cast<unsigned>(slot)] = static_cast<std::uint32_t>(state_.state);
        }
        state_.output = state_.shuffle[0];
    }
    state_.state = step(state_.state);
    const auto index = state_.output / 0x4000000u;
    if (index >= state_.shuffle.size()) throw std::logic_error("default-stream shuffle invariant failed");
    state_.output = state_.shuffle[index];
    state_.shuffle[index] = static_cast<std::uint32_t>(state_.state);
    return state_.output;
}
std::int32_t ProfileUniformRandom::integer(std::int32_t low, std::int32_t high) {
    const auto low_word = std::bit_cast<std::uint32_t>(low);
    const auto delta = std::bit_cast<std::uint32_t>(high) - low_word;
    const auto range = delta + 1u;
    if (range <= 1u || delta > 0x7fffffffu) return low;
    const auto limit = 0x7fffffffu - (0x80000000u % range);
    std::uint32_t value;
    do { value = generate(); } while (value > limit);
    return std::bit_cast<std::int32_t>(low_word + value % range);
}

float ProfileUniformRandom::real(float low, float high) {
    // The profile's default method draws before inspecting its endpoints.
    const auto draw = std::bit_cast<std::int32_t>(generate());
    constexpr double scale = std::bit_cast<double>(std::uint64_t{0x3e00000000200000});
    constexpr double cap_threshold = std::bit_cast<double>(std::uint64_t{0x3fefffffbf935359});
    constexpr float cap = std::bit_cast<float>(std::uint32_t{0x3f7ffffe});

    const __m128i word = _mm_cvtsi32_si128(draw);
    const __m128d converted = _mm_cvtepi32_pd(word);
    const __m128d scaled = _mm_mul_sd(converted, _mm_set_sd(scale));
    __m128 factor = _mm_cvtpd_ps(scaled);
    if (_mm_comigt_sd(_mm_cvtps_pd(factor), _mm_set_sd(cap_threshold)))
        factor = _mm_set_ss(cap);

    const __m128 low_word = _mm_set_ss(low);
    const __m128 delta = _mm_sub_ss(_mm_set_ss(high), low_word);
    const __m128 product = _mm_mul_ss(delta, factor);
    return _mm_cvtss_f32(_mm_add_ss(product, low_word));
}
}
