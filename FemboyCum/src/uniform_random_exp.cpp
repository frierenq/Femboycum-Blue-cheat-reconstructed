#include "fc/uniform_random.hpp"
#include "uniform_random_exp_tables.inc"

#include <bit>
#include <cstdint>
#include <emmintrin.h>
#include <stdexcept>

namespace fc {
namespace {

double as_double(std::uint64_t bits) noexcept { return std::bit_cast<double>(bits); }
__m128d scalar(std::uint64_t bits) noexcept { return _mm_set_sd(as_double(bits)); }
__m128d pair(std::uint64_t low, std::uint64_t high) noexcept {
    return _mm_set_pd(as_double(high), as_double(low));
}
std::uint64_t low_bits(__m128d word) noexcept {
    return std::bit_cast<std::uint64_t>(_mm_cvtsd_f64(word));
}
__m128 from_bits(std::uint32_t bits) noexcept {
    return _mm_set_ss(std::bit_cast<float>(bits));
}
__m128 overflow_positive_infinity() noexcept {
    // Both native finite-saturation branches share 0x1002855c..0x10028572:
    // ECX=0, OR 0x7f7f, PINSRW word 1, then ADDSS the finite word to itself.
    // Returning an infinity constant would omit the overflow/precision flags.
    const __m128 large = from_bits(0x7f7f0000u);
    return _mm_add_ss(large, large);
}
__declspec(noinline) __m128 divide_positive_one(__m128 denominator) noexcept {
    // The installed helper executes DIVSS +1/+0 even though it returns an
    // independently formed +infinity. In the supported zero-factor branch,
    // the quotient has exactly the same bits and preserves MXCSR ZE.
    return _mm_div_ss(from_bits(0x3f800000u), denominator);
}
__declspec(noinline) __m128 underflow_positive_zero(__m128 minimum_normal) noexcept {
    // 0x1002857f squares binary32 minimum normal before returning +0. The
    // product is unused natively; XMM0 is zeroed separately afterward.
    // Force the discarded instruction result through a volatile store so
    // release optimization retains the MXCSR UE/PE side effects, then return
    // independent +0 even if a nondefault rounding mode changes the product.
    volatile float discarded = _mm_cvtss_f32(_mm_mul_ss(minimum_normal,
                                                         minimum_normal));
    (void)discarded;
    return from_bits(0u);
}
__m128d doubled_word(std::uint16_t word) noexcept {
    return scalar(std::uint64_t{word} << 48);
}

// The only valid inputs here are the proved default factor (+0 or positive
// normal below one) and any binary32 exponent except ordered equal 1.0f.
// The NaN-exponent branch uses the decoded helper's ADDSS-self instruction.
// General native NaN payload parity, full FP-status parity/traps, and nondefault
// MXCSR are outside this bounded model; selected overflow/underflow/DZ
// instruction side effects are reproduced under masked round-to-nearest SSE.
// Every normal finite path below follows the
// instruction/lane order in research/vstdlib-rng/float-helper-finite.md.
__m128 powered_factor(float factor, float exponent) {
    const auto base_bits = std::bit_cast<std::uint32_t>(factor);
    const auto exponent_bits = std::bit_cast<std::uint32_t>(exponent);
    const auto magnitude = exponent_bits & 0x7fffffffu;
    const bool negative = (exponent_bits & 0x80000000u) != 0;

    if (base_bits != 0 && (base_bits < 0x00800000u || base_bits > 0x3f7ffffeu))
        throw std::logic_error("factor outside proved default-stream domain");
    if (magnitude == 0) return from_bits(0x3f800000u);
    if (magnitude > 0x7f800000u) {
        // 0x10028481..0x10028492 reloads the original float exponent and
        // executes ADDSS xmm1,xmm1, quieting a signaling NaN while retaining
        // its payload under the selected masked SSE mode.
        const __m128 original = from_bits(exponent_bits);
        return _mm_add_ss(original, original);
    }
    if (magnitude == 0x7f800000u) {
        if (negative && base_bits == 0)
            return divide_positive_one(from_bits(base_bits));
        return from_bits(negative ? 0x7f800000u : 0u);
    }
    if (base_bits == 0)
        return negative ? divide_positive_one(from_bits(base_bits)) : from_bits(0u);

    // 0x10027f49..0x10027fb8: normal binary32 exponent/mantissa extraction.
    const auto exponent_word = base_bits >> 16;
    const auto mantissa_bits = ((std::uint64_t{base_bits} << 29) &
                                0x000fffffffffffffULL) | 0x3ff0000000000000ULL;
    const unsigned table_index = ((((exponent_word & 0x7fu) + 1u) & 0xfeu) >> 1);
    const auto integer_log = (static_cast<std::int32_t>(exponent_word) - 0x3f3f) >> 7;

    // 0x10027fbe..0x10028029: B is split by PSRLQ/PSLLQ (low 26 bits
    // cleared). The two MULSD paths and final additions retain their order.
    __m128d xmm1 = _mm_cvtss_sd(_mm_setzero_pd(), from_bits(exponent_bits));
    __m128d xmm5 = scalar(mantissa_bits);
    const auto b_bits = detail::kLogB[table_index];
    __m128d xmm7 = scalar(b_bits & ~((std::uint64_t{1} << 26) - 1));
    __m128d xmm3 = scalar(b_bits);
    xmm3 = _mm_sub_sd(xmm3, xmm7);
    xmm7 = _mm_mul_sd(xmm7, xmm5);
    xmm5 = _mm_mul_sd(xmm5, xmm3);
    xmm7 = _mm_sub_sd(xmm7, scalar(detail::kLogB[0]));
    xmm5 = _mm_add_sd(xmm5, xmm7);

    // 0x10028029..0x1002805f: logarithm polynomial and exponent*32.
    __m128d xmm0 = scalar(detail::kLogA[table_index]);
    xmm7 = _mm_unpacklo_pd(xmm5, xmm5);
    xmm3 = scalar(detail::kMagic);
    xmm0 = _mm_add_sd(xmm0, xmm5);
    __m128d xmm6 = pair(detail::kC0, detail::kC1);
    xmm6 = _mm_mul_pd(xmm6, xmm7);
    xmm7 = _mm_mul_pd(xmm7, xmm7);
    const __m128i log_integer = _mm_cvtsi32_si128(integer_log);
    xmm0 = _mm_add_sd(xmm0, _mm_cvtepi32_pd(log_integer));
    __m128d xmm2 = pair(detail::kD0, detail::kD1);
    xmm2 = _mm_mul_sd(xmm2, xmm7);
    xmm0 = _mm_add_sd(xmm0, xmm2);
    xmm2 = _mm_unpackhi_pd(xmm2, xmm2);
    xmm6 = _mm_add_sd(xmm6, xmm2);
    xmm1 = _mm_mul_sd(xmm1, scalar(detail::kThirtyTwo));
    xmm0 = _mm_mul_sd(xmm0, xmm1);
    xmm7 = _mm_mul_sd(xmm7, xmm7); // low r^4, high r^2

    // 0x1002805f..0x1002808f: first lattice range decision. The original
    // ADD/SUB magic rounding precedes the slow-path branch.
    const auto high_word = static_cast<std::uint16_t>(low_bits(xmm0) >> 48);
    const auto masked_word = static_cast<std::uint32_t>(high_word & 0x7ff0u);
    __m128d xmm4 = xmm0;
    xmm0 = _mm_add_sd(xmm0, xmm3);
    xmm0 = _mm_sub_sd(xmm0, xmm3);
    xmm6 = _mm_mul_pd(xmm6, xmm7);
    const auto first_gate = (0x41d0u - masked_word) | (masked_word - 0x3e60u);
    if (first_gate >= 0x80000000u) {
        if (masked_word <= 0x3e60u) return from_bits(0x3f800000u);
        if (high_word & 0x8000u)
            return underflow_positive_zero(from_bits(0x00800000u));
        return overflow_positive_infinity();
    }

    // 0x10028095..0x100280e0: integer lattice, retained high SSE lane, and
    // residual correction. CVTSD2SI sees an already rounded integral double.
    const std::int32_t lattice = _mm_cvtsd_si32(xmm0);
    xmm4 = _mm_sub_sd(xmm4, xmm0);
    xmm7 = _mm_unpackhi_pd(xmm6, xmm6);
    xmm6 = _mm_add_sd(xmm6, xmm7);
    xmm7 = pair(detail::kE0, detail::kE1);
    xmm1 = _mm_mul_sd(xmm1, xmm6);
    xmm2 = pair(detail::kF0, detail::kF1);
    xmm4 = _mm_add_sd(xmm4, xmm1);
    xmm5 = _mm_unpacklo_pd(xmm4, xmm4);
    const auto second_gate = (0xfbfu - static_cast<std::uint32_t>(lattice)) |
                             (static_cast<std::uint32_t>(lattice) + 0xfa0u);
    const bool split_scale = second_gate >= 0x80000000u;
    if (split_scale && lattice >= 0x2000) return overflow_positive_infinity();
    if (split_scale && lattice <= -0x2000)
        return underflow_positive_zero(from_bits(0x00800000u));

    // 0x100280e6..0x1002813a (ordinary) or 0x100284d5..0x1002855b
    // (split): EXP_T is indexed by the low five lattice bits. The binary64
    // exponent words reproduce PINSRW and preserve the original MUL/ADD order.
    const auto index = static_cast<unsigned>(lattice) & 0x1fu;
    xmm3 = scalar(detail::kExpT[index]);
    __m128d final_scale = _mm_setzero_pd();
    if (split_scale) {
        const auto quotient = lattice >> 5;
        const auto half_floor = quotient >> 1;
        const auto half_ceil = quotient - half_floor;
        const auto scale_word = static_cast<std::uint16_t>(0x3ff0 + half_floor * 16);
        const auto final_word = static_cast<std::uint16_t>((0x3ff + half_ceil) * 16);
        xmm6 = doubled_word(scale_word);
        final_scale = doubled_word(final_word);
    } else {
        // SAR, not SHR, is required for negative lattice values.
        const auto half = lattice >> 1;
        const auto aligned = static_cast<std::uint32_t>(half) & 0xfffffff0u;
        const auto scale_word = static_cast<std::uint16_t>(0x3ff0u + aligned);
        xmm6 = doubled_word(scale_word);
    }
    xmm7 = _mm_mul_pd(xmm7, xmm5);
    xmm5 = _mm_mul_sd(xmm5, xmm5);
    xmm4 = _mm_mul_sd(xmm4, xmm3);
    xmm2 = _mm_add_pd(xmm2, xmm7);
    xmm3 = _mm_mul_sd(xmm3, xmm6);
    xmm4 = _mm_mul_sd(xmm4, xmm6);
    xmm5 = _mm_mul_sd(xmm5, xmm2);
    xmm0 = _mm_unpackhi_pd(xmm2, xmm2);
    xmm0 = _mm_add_sd(xmm0, xmm5);
    xmm0 = _mm_mul_sd(xmm0, xmm4);
    xmm0 = _mm_add_sd(xmm0, xmm3);
    if (split_scale) xmm0 = _mm_mul_sd(xmm0, final_scale);
    return _mm_cvtpd_ps(xmm0);
}

} // namespace

float ProfileUniformRandom::real_exp(float low, float high, float exponent) {
    // This duplicates the profile's exact factor stage to leave ordinary
    // RandomFloat's previously verified source/disassembly intact.
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

    if (std::bit_cast<std::uint32_t>(exponent) != 0x3f800000u)
        factor = powered_factor(_mm_cvtss_f32(factor), exponent);
    const __m128 low_word = _mm_set_ss(low);
    const __m128 delta = _mm_sub_ss(_mm_set_ss(high), low_word);
    const __m128 product = _mm_mul_ss(delta, factor);
    return _mm_cvtss_f32(_mm_add_ss(product, low_word));
}
} // namespace fc
