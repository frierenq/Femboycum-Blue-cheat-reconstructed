#include "fc/uniform_random.hpp"
#include "fc/mock.hpp"

#include <array>
#include <bit>
#include <cmath>
#include <cstdint>
#include <emmintrin.h>
#include <iostream>
#include <limits>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

namespace {
using fc::ProfileUniformRandom;

void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

std::int32_t parse_i32(const std::string& word) {
    const auto value = std::stoll(word);
    if (value < std::numeric_limits<std::int32_t>::min() ||
        value > std::numeric_limits<std::int32_t>::max())
        throw std::runtime_error("probe input outside signed x86 word");
    return static_cast<std::int32_t>(value);
}

std::uint32_t parse_u32(const std::string& word) {
    const auto value = std::stoull(word, nullptr, 0);
    if (value > std::numeric_limits<std::uint32_t>::max())
        throw std::runtime_error("probe input outside unsigned x86 word");
    return static_cast<std::uint32_t>(value);
}

void emit(char kind, const ProfileUniformRandom& rng) {
    const auto snapshot = rng.snapshot();
    std::cout << kind << ' ' << snapshot.state << ' ' << snapshot.output
              << ' ' << snapshot.generation_calls;
    for (const auto value : snapshot.shuffle) std::cout << ' ' << value;
    std::cout << '\n';
}
template <class T>
void emit(char kind, T value, const ProfileUniformRandom& rng) {
    const auto snapshot = rng.snapshot();
    std::cout << kind << ' ' << value << ' ' << snapshot.state << ' '
              << snapshot.output << ' ' << snapshot.generation_calls;
    for (const auto word : snapshot.shuffle) std::cout << ' ' << word;
    std::cout << '\n';
}

void probe() {
    auto rng = std::make_unique<ProfileUniformRandom>();
    std::string line;
    while (std::getline(std::cin, line)) {
        std::istringstream input(line);
        std::string kind, first, second, extra;
        input >> kind;
        if (kind == "N") {
            check(!(input >> extra), "N takes no arguments");
            rng = std::make_unique<ProfileUniformRandom>();
            emit('N', *rng);
        } else if (kind == "S") {
            check(bool(input >> first) && !(input >> extra), "S takes one argument");
            rng->seed(parse_i32(first));
            emit('S', *rng);
        } else if (kind == "G") {
            check(!(input >> extra), "G takes no arguments");
            emit('G', rng->generate(), *rng);
        } else if (kind == "I") {
            check(bool(input >> first >> second) && !(input >> extra), "I takes two arguments");
            emit('I', rng->integer(parse_i32(first), parse_i32(second)), *rng);
        } else if (kind == "F") {
            check(bool(input >> first >> second) && !(input >> extra), "F takes two float-bit arguments");
            const auto low = std::bit_cast<float>(parse_u32(first));
            const auto high = std::bit_cast<float>(parse_u32(second));
            emit('F', std::bit_cast<std::uint32_t>(rng->real(low, high)), *rng);
        } else if (kind == "E") {
            std::string third;
            check(bool(input >> first >> second >> third) && !(input >> extra),
                  "E takes three float-bit arguments");
            const auto low = std::bit_cast<float>(parse_u32(first));
            const auto high = std::bit_cast<float>(parse_u32(second));
            const auto exponent = std::bit_cast<float>(parse_u32(third));
            emit('E', std::bit_cast<std::uint32_t>(rng->real_exp(low, high, exponent)), *rng);
        } else if (kind == "M") {
            check(!(input >> extra), "M takes no arguments");
            emit('M', _mm_getcsr(), *rng);
        } else {
            throw std::runtime_error("unknown probe command");
        }
    }
}

void owned_integration() {
    fc::MockEngine engine;
    fc::MockScripts scripts;
    fc::RecordingRenderer renderer;
    fc::Core core(engine, scripts, renderer);
    bool inactive = false;
    try { core.research_random_seed(1); } catch (const std::logic_error&) { inactive = true; }
    check(inactive, "owned RNG requires initialized core");
    core.initialize();
    core.research_random_seed(1);
    check(core.research_random_int(0, 2147483646) == 893351816, "owned first draw");
    core.research_hurt_profile_rng(fc::EntitySlot::checked(64));
    check(core.research_state(fc::EntitySlot::checked(64)).second == 2 &&
          core.research_random_generation_count() == 2,
          "hurt consumes the shared second draw");
    core.research_hurt_profile_rng(fc::EntitySlot::checked(64));
    check(core.research_state(fc::EntitySlot::checked(64)).second == 1 &&
          core.research_random_generation_count() == 2,
          "nonzero hurt transition consumes no draw");
    check(core.research_random_int(0, 2147483646) == 1624379149,
          "integer API continues after hurt draw");
    core.research_reset_arrays();
    check(core.research_random_generation_count() == 3,
          "body-yaw reset does not reset owned RNG");
    core.research_random_seed(1);
    check(core.research_random_generation_count() == 3, "reseed preserves instrumentation count");
    core.research_hurt_profile_rng(fc::EntitySlot::checked(0));
    check(core.research_state(fc::EntitySlot::checked(0)).second == 1 &&
          core.research_random_generation_count() == 4,
          "reseeded zero selected state draws once");
    core.shutdown();
    core.initialize();
    check(core.research_random_generation_count() == 0, "new owned core state has fresh RNG");
    core.research_random_seed(1);
    check(core.research_random_float_exp(10.0f, 20.0f, 0.0f) == 20.0f &&
          core.research_random_generation_count() == 1,
          "owned zero exponent retains one-draw behavior");
    check(core.research_random_int(0, 2147483646) == 197493099 &&
          core.research_random_generation_count() == 2,
          "integer API continues the exponent stream");
    core.research_random_seed(std::numeric_limits<std::int32_t>::max());
    check(std::bit_cast<std::uint32_t>(core.research_random_float_exp(0.0f, 1.0f, -1.0f)) ==
              0x7f800000u && core.research_random_generation_count() == 3,
          "owned exponent helper handles zero factor without losing state");
    core.research_hurt_profile_rng(fc::EntitySlot::checked(64));
    check(core.research_state(fc::EntitySlot::checked(64)).second == 1 &&
          core.research_random_generation_count() == 4,
          "hurt shares exponent zero-output reinitialization");
    core.shutdown();
    inactive = false;
    try { (void)core.research_random_float_exp(0.0f, 1.0f, 2.0f); }
    catch (const std::logic_error&) { inactive = true; }
    check(inactive, "owned exponent API rejects inactive core");
}

void golden() {
    owned_integration();
    constexpr std::array<std::uint32_t, 5> seed_one{
        893351816u, 197493099u, 1624379149u, 1137522503u, 1998097157u
    };
    constexpr std::array<std::uint32_t, 5> seed_12345{
        1982386332u, 715426902u, 424962143u, 2038867620u, 1683198519u
    };
    for (const auto seed : {0, 1, -1, std::numeric_limits<std::int32_t>::min()}) {
        ProfileUniformRandom rng;
        rng.seed(seed);
        for (const auto expected : seed_one)
            check(rng.generate() == expected, "seed 0/+1/-1/INT_MIN vector");
    }
    for (const auto seed : {12345, -12345}) {
        ProfileUniformRandom rng;
        rng.seed(seed);
        for (const auto expected : seed_12345)
            check(rng.generate() == expected, "positive/negative seed vector");
    }
    {
        ProfileUniformRandom rng;
        rng.seed(std::numeric_limits<std::int32_t>::max());
        check(rng.generate() == 0, "INT_MAX first zero draw");
        check(rng.generate() == seed_one[0], "zero output reinitializes");
        check(rng.snapshot().generation_calls == 2, "zero draw counted");
    }
    {
        ProfileUniformRandom rng;
        rng.seed(1);
        const auto before = rng.snapshot().generation_calls;
        check(std::bit_cast<std::uint32_t>(rng.real(17.5f, 17.5f)) == 0x418c0000u,
              "equal finite float endpoints retain value");
        check(rng.snapshot().generation_calls == before + 1,
              "equal float endpoints still consume one draw");
    }
    {
        ProfileUniformRandom rng;
        rng.seed(std::numeric_limits<std::int32_t>::max());
        check(std::bit_cast<std::uint32_t>(rng.real(10.0f, 20.0f)) == 0x41200000u,
              "zero draw returns finite low endpoint");
        check(rng.snapshot().generation_calls == 1 && rng.snapshot().output == 0,
              "zero float draw preserves generator state effect");
        (void)rng.real(10.0f, 20.0f);
        check(rng.snapshot().generation_calls == 2 && rng.snapshot().output != 0,
              "next float draw reinitializes after zero output");
    }
    {
        ProfileUniformRandom rng;
        rng.seed(1);
        check(std::bit_cast<std::uint32_t>(rng.real_exp(10.0f, 20.0f, 0.0f)) ==
                  0x41a00000u,
              "zero exponent transforms factor to one");
        check(rng.snapshot().generation_calls == 1, "zero exponent still draws once");
    }
    {
        ProfileUniformRandom ordinary;
        ProfileUniformRandom exponential;
        ordinary.seed(12345);
        exponential.seed(12345);
        check(std::bit_cast<std::uint32_t>(ordinary.real(-15.0f, 21.0f)) ==
                  std::bit_cast<std::uint32_t>(exponential.real_exp(-15.0f, 21.0f, 1.0f)),
              "ordered unit exponent skips helper");
        check(ordinary.snapshot().output == exponential.snapshot().output &&
                  ordinary.snapshot().generation_calls == exponential.snapshot().generation_calls,
              "unit exponent uses same stream state");
    }
    {
        ProfileUniformRandom rng;
        rng.seed(std::numeric_limits<std::int32_t>::max());
        check(std::bit_cast<std::uint32_t>(rng.real_exp(0.0f, 1.0f, -1.0f)) ==
                  0x7f800000u,
              "zero factor negative exponent produces positive infinity");
        check(rng.snapshot().generation_calls == 1 && rng.snapshot().output == 0,
              "exceptional helper path preserves one-draw state");
    }
    {
        // The installed helper's large-positive first-gate branch doubles
        // finite 0x7f7f0000 to +infinity, setting overflow and precision.
        struct RestoreMxcsr {
            unsigned original = _mm_getcsr();
            ~RestoreMxcsr() { _mm_setcsr(original); }
        } restore;
        ProfileUniformRandom rng;
        rng.seed(1);
        _mm_setcsr(0x1f80u);
        const auto value = rng.real_exp(0.0f, 1.0f,
            std::bit_cast<float>(0xff7fffffu));
        const auto status = _mm_getcsr();
        check(std::bit_cast<std::uint32_t>(value) == 0x7f800000u,
              "large negative exponent retains positive infinity result");
        check((status & 0x28u) == 0x28u && (status & ~0x3fu) == 0x1f80u,
              "native ADDSS saturation sets overflow/precision under unchanged controls");
        check(rng.snapshot().generation_calls == 1,
              "overflowing helper branch still consumes one draw");
    }
    {
        struct RestoreMxcsr {
            unsigned original = _mm_getcsr();
            ~RestoreMxcsr() { _mm_setcsr(original); }
        } restore;
        // INT_MAX's first generator output is +0. The finite negative route
        // uses DIVSS at 0x100282e8; -infinity uses a distinct DIVSS at
        // 0x10028432. Both return +infinity with MXCSR divide-by-zero set.
        for (const auto exponent_bits : {0xbf800000u, 0xff800000u, 0xff7fffffu}) {
            ProfileUniformRandom rng;
            rng.seed(std::numeric_limits<std::int32_t>::max());
            _mm_setcsr(0x1f80u);
            const auto value = rng.real_exp(0.0f, 1.0f,
                                            std::bit_cast<float>(exponent_bits));
            const auto status = _mm_getcsr();
            check(std::bit_cast<std::uint32_t>(value) == 0x7f800000u,
                  "zero-factor negative exponent retains positive infinity");
            check(status == 0x1f84u,
                  "native zero-factor DIVSS sets only ZE under selected controls");
            check(rng.snapshot().generation_calls == 1 && rng.snapshot().output == 0,
                  "zero-factor DIVSS retains one-draw state");
        }
    }
    {
        struct RestoreMxcsr {
            unsigned original = _mm_getcsr();
            ~RestoreMxcsr() { _mm_setcsr(original); }
        } restore;
        // First-gate and integer-lattice negative saturation both execute
        // 0x1002857f MULSS(minimum-normal, minimum-normal) before returning +0.
        for (const auto exponent_bits : {0x7f7fffffu, 0x45000000u}) {
            ProfileUniformRandom rng;
            rng.seed(1);
            _mm_setcsr(0x1f80u);
            const auto value = rng.real_exp(0.0f, 1.0f,
                                            std::bit_cast<float>(exponent_bits));
            const auto status = _mm_getcsr();
            check(std::bit_cast<std::uint32_t>(value) == 0x00000000u,
                  "negative saturation retains positive zero");
            check(status == 0x1fb0u,
                  "native negative saturation MULSS sets underflow/precision");
            check(rng.snapshot().generation_calls == 1 &&
                      rng.snapshot().output == 893351816,
                  "negative saturation retains one-draw stream state");
        }
    }
    {
        ProfileUniformRandom rng;
        rng.seed(1);
        const auto nan = std::bit_cast<float>(0x7fc00001u);
        check(std::isnan(rng.real_exp(0.0f, 1.0f, nan)),
              "unordered exponent enters helper NaN branch");
        check(rng.snapshot().generation_calls == 1,
              "NaN exponent still consumes one draw");
    }
    {
        constexpr std::array<std::pair<std::uint32_t, std::uint32_t>, 4> cases{{
            {0x7fc12345u, 0x7fc12345u}, {0x7fa12345u, 0x7fe12345u},
            {0xffc12345u, 0xffc12345u}, {0xffa12345u, 0xffe12345u},
        }};
        for (const auto seed : {1, std::numeric_limits<std::int32_t>::max()}) {
            for (const auto [exponent_bits, expected_bits] : cases) {
                ProfileUniformRandom rng;
                rng.seed(seed);
                const auto result = rng.real_exp(0.0f, 1.0f,
                    std::bit_cast<float>(exponent_bits));
                check(std::bit_cast<std::uint32_t>(result) == expected_bits,
                      "owned decoded ADDSS-self NaN exponent payload");
                check(rng.snapshot().generation_calls == 1,
                      "NaN exponent result retains exactly one draw");
            }
        }
    }
    {
        ProfileUniformRandom rng;
        rng.seed(1);
        const std::array<std::int32_t, 6> values{
            893351816, 197493099, 1137522503, 823564440, 143542612, 823378840
        };
        const std::array<std::uint64_t, 6> counts{1, 2, 4, 6, 8, 11};
        for (std::size_t i = 0; i < values.size(); ++i) {
            check(rng.integer(0, 1300000000) == values[i], "rejection-mapped value");
            check(rng.snapshot().generation_calls == counts[i], "rejected draws consumed");
        }
    }
    {
        ProfileUniformRandom rng;
        rng.seed(1);
        check(rng.integer(77, 77) == 77, "equal endpoints fallback");
        check(rng.integer(10, 5) == 10, "reversed endpoints fallback");
        check(rng.integer(std::numeric_limits<std::int32_t>::min(),
                          std::numeric_limits<std::int32_t>::max()) ==
                  std::numeric_limits<std::int32_t>::min(),
              "full signed span fallback");
        check(rng.snapshot().generation_calls == 0, "fallback consumes no draw");
    }
    {
        ProfileUniformRandom rng;
        rng.seed(1);
        constexpr std::array<std::int32_t, 8> wrapped{
            -2147483646, 2147483645, 2147483643, -2147483643,
            2147483647, 2147483642, -2147483648, 2147483646
        };
        for (const auto expected : wrapped)
            check(rng.integer(2147483642, -2147483643) == expected,
                  "wrapped endpoint mapping");
    }
    {
        ProfileUniformRandom rng;
        rng.seed(12345);
        (void)rng.generate();
        const auto before = rng.snapshot();
        rng.seed(-12345);
        const auto after = rng.snapshot();
        check(after.state == -12345 && after.output == 0, "seed writes state/output");
        check(after.shuffle == before.shuffle, "seed preserves shuffle table");
        check(after.generation_calls == before.generation_calls,
              "seed does not count a generation");
    }
}
} // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "--probe") {
            probe();
        } else if (argc == 1) {
            golden();
            std::cout << "uniform_random_tests: ok\n";
        } else {
            throw std::runtime_error("usage: uniform_random_tests [--probe]");
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
