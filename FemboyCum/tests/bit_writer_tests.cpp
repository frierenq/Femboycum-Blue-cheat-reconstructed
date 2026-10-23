#include "fc/bit_writer.hpp"

#include <array>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using fc::BitWriter20Snapshot;
using fc::ResearchBitWriter20;

void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

// Separate handwritten model of the selected word-mask operand semantics.
// This is not an interpreter that executes freshly decoded original bytes.
// Production code writes bits individually; this combines affected words.
struct WordInterpreter {
    std::array<std::uint32_t, 5> words{};
    std::uint32_t cursor{};
    bool overflow{};

    void block(std::uint32_t value, unsigned count) {
        if (cursor + count > 160) {
            cursor = 160;
            return;
        }
        const auto word_index = cursor / 32;
        const auto shift = cursor % 32;
        std::uint64_t window = words[word_index];
        if (word_index + 1 < words.size()) {
            window |= static_cast<std::uint64_t>(words[word_index + 1]) << 32;
        }
        const auto mask = ((std::uint64_t{1} << count) - 1) << shift;
        window = (window & ~mask) | ((static_cast<std::uint64_t>(value) << shift) & mask);
        words[word_index] = static_cast<std::uint32_t>(window);
        if (word_index + 1 < words.size() && shift + count > 32) {
            words[word_index + 1] = static_cast<std::uint32_t>(window >> 32);
        }
        cursor += count;
    }

    void one(bool bit) {
        if (cursor >= 160) {
            overflow = true;
        } else if (!overflow) {
            const auto index = cursor / 32;
            const auto mask = std::uint32_t{1} << (cursor % 32);
            words[index] = bit ? words[index] | mask : words[index] & ~mask;
            ++cursor;
        }
    }

    void bits(std::uint32_t value, unsigned count) { block(value, count); }

    void coord(float value) {
        const auto integer = static_cast<std::uint32_t>(std::fabs(value));
        const auto scaled = static_cast<std::int32_t>(32.0f * value);
        const auto fraction = static_cast<std::uint32_t>(scaled < 0 ? -scaled : scaled) & 31u;
        one(integer != 0);
        one(fraction != 0);
        if (integer == 0 && fraction == 0) return;
        one(value <= -0.03125f);
        if (integer != 0) block(integer - 1u, 14);
        if (fraction != 0) block(fraction, 5);
    }

    void crypt(std::span<const std::uint8_t> key) {
        if (key.empty()) return;
        std::array<std::uint8_t, 20> pad{};
        for (std::size_t i = 0; i < pad.size(); ++i) pad[i] = key[i % key.size()];
        for (std::size_t i = 0; i < pad.size(); ++i) {
            const auto wi = i / 4;
            const auto shift = static_cast<unsigned>((i % 4) * 8);
            words[wi] ^= static_cast<std::uint32_t>(pad[i]) << shift;
        }
    }

    BitWriter20Snapshot snapshot() const {
        BitWriter20Snapshot out;
        for (std::size_t i = 0; i < out.data.size(); ++i) {
            out.data[i] = static_cast<std::uint8_t>(words[i / 4] >> ((i % 4) * 8));
        }
        out.bit_cursor = cursor;
        out.overflow = overflow;
        return out;
    }
};

void same(const ResearchBitWriter20& writer, const WordInterpreter& model,
          const std::string& action) {
    if (writer.snapshot() != model.snapshot()) {
        throw std::runtime_error("handwritten word model mismatch after " + action);
    }
    check(writer.is_overflowed() == model.overflow, "overflow getter mismatch");
}

void bit_order_and_word_crossing() {
    ResearchBitWriter20 writer;
    WordInterpreter model;
    writer.write_bits(0xabcde, 20);
    model.bits(0xabcde, 20);
    same(writer, model, "first 20 bits");
    check(writer.snapshot().data[0] == 0xde && writer.snapshot().data[1] == 0xbc &&
          writer.snapshot().data[2] == 0x0a, "LSB-first byte order changed");
    writer.write_bits(5, 3);
    model.bits(5, 3);
    same(writer, model, "unaligned append");
    check(writer.snapshot().data[2] == 0x5a, "unaligned byte mask changed");

    ResearchBitWriter20 crossing;
    WordInterpreter crossing_model;
    crossing.write_bits(0, 31);
    crossing_model.bits(0, 31);
    crossing.write_bits(0x17, 5);
    crossing_model.bits(0x17, 5);
    same(crossing, crossing_model, "32-bit word crossing");
    check(crossing.snapshot().data[3] == 0x80 && crossing.snapshot().data[4] == 0x0b,
          "cross-word payload bits changed");
}

void capacity_clamp_does_not_signal_overflow() {
    ResearchBitWriter20 writer;
    WordInterpreter model;
    for (int i = 0; i < 5; ++i) {
        writer.write_bits(0xa5a5a5a5, 32);
        model.bits(0xa5a5a5a5, 32);
        same(writer, model, "fill 160 bits");
    }
    const auto full = writer.snapshot();
    writer.write_bits(1, 1);
    model.bits(1, 1);
    same(writer, model, "block capacity miss");
    check(writer.snapshot().bit_cursor == 160 && !writer.is_overflowed() &&
          writer.snapshot().data == full.data, "block miss must clamp only");
    writer.write_coord(0.0f);
    model.coord(0.0f);
    same(writer, model, "single-bit capacity miss");
    check(writer.is_overflowed(), "single-bit miss must set overflow flag");
}

void partial_coordinate_blocks() {
    ResearchBitWriter20 integer_writer;
    WordInterpreter integer_model;
    for (int i = 0; i < 4; ++i) {
        integer_writer.write_bits(0, 32);
        integer_model.bits(0, 32);
    }
    integer_writer.write_bits(0, 22);
    integer_model.bits(0, 22);
    integer_writer.write_coord(1.0f);
    integer_model.coord(1.0f);
    same(integer_writer, integer_model, "14-bit block capacity miss");
    const auto integer_state = integer_writer.snapshot();
    check(integer_state.bit_cursor == 160 && !integer_state.overflow &&
          integer_state.data[18] == 0x40, "integer block miss must preserve earlier flag bit");

    ResearchBitWriter20 fraction_writer;
    WordInterpreter fraction_model;
    for (int i = 0; i < 4; ++i) {
        fraction_writer.write_bits(0, 32);
        fraction_model.bits(0, 32);
    }
    fraction_writer.write_bits(0, 28);
    fraction_model.bits(0, 28);
    fraction_writer.write_coord(0.5f);
    fraction_model.coord(0.5f);
    same(fraction_writer, fraction_model, "5-bit block capacity miss");
    const auto fraction_state = fraction_writer.snapshot();
    check(fraction_state.bit_cursor == 160 && !fraction_state.overflow &&
          fraction_state.data[19] == 0x20, "fraction block miss must preserve earlier flag bit");
}

void coordinate_encoding() {
    ResearchBitWriter20 writer;
    WordInterpreter model;
    writer.write_coord(-1.5f);
    model.coord(-1.5f);
    same(writer, model, "negative integer/fraction coordinate");
    const auto state = writer.snapshot();
    check(state.bit_cursor == 22 && state.data[0] == 0x07 && state.data[2] == 0x20,
          "negative coordinate layout changed");

    ResearchBitWriter20 small;
    WordInterpreter small_model;
    small.write_coord(-0.03125f);
    small_model.coord(-0.03125f);
    same(small, small_model, "negative fractional coordinate");
    check(small.snapshot().bit_cursor == 8 && small.snapshot().data[0] == 0x0e,
          "fraction/sign layout changed");

    ResearchBitWriter20 zero;
    zero.write_coord(-0.0f);
    check(zero.snapshot().bit_cursor == 2 && zero.snapshot().data[0] == 0,
          "negative zero should write only two absent flags");
}

void fractional_end_and_float_boundaries() {
    ResearchBitWriter20 exact;
    WordInterpreter exact_model;
    for (int i = 0; i < 4; ++i) {
        exact.write_bits(0, 32);
        exact_model.bits(0, 32);
    }
    exact.write_bits(0, 24);
    exact_model.bits(0, 24);
    exact.write_coord(0.03125f);
    exact_model.coord(0.03125f);
    same(exact, exact_model, "fraction lands on bit 159");
    check(exact.snapshot().bit_cursor == 160 && exact.snapshot().data[19] == 0x0a &&
          !exact.is_overflowed(), "last fractional bit encoding changed");

    ResearchBitWriter20 short_one;
    WordInterpreter short_model;
    for (int i = 0; i < 4; ++i) {
        short_one.write_bits(0, 32);
        short_model.bits(0, 32);
    }
    short_one.write_bits(0, 25);
    short_model.bits(0, 25);
    short_one.write_coord(0.03125f);
    short_model.coord(0.03125f);
    same(short_one, short_model, "fraction block misses at 153");
    check(short_one.snapshot().bit_cursor == 160 &&
          short_one.snapshot().data[19] == 0x04 && !short_one.is_overflowed(),
          "failed fractional block changed earlier flags or overflow");

    for (float tiny : {std::numeric_limits<float>::denorm_min(),
                       -std::numeric_limits<float>::denorm_min(),
                       std::numeric_limits<float>::min(),
                       -std::numeric_limits<float>::min(), -0.0f}) {
        ResearchBitWriter20 writer;
        WordInterpreter model;
        writer.write_coord(tiny);
        model.coord(tiny);
        same(writer, model, "subnormal, minimum normal, or negative zero");
        check(writer.snapshot().bit_cursor == 2 && writer.snapshot().data[0] == 0,
              "tiny finite float should encode two absent flags");
    }
}

void bit_count_edges() {
    ResearchBitWriter20 writer;
    WordInterpreter model;
    writer.write_bits(0x7fffffff, 31);
    model.bits(0x7fffffff, 31);
    same(writer, model, "31-bit all-ones block");
    writer.write_bits(0x89abcdef, 32);
    model.bits(0x89abcdef, 32);
    same(writer, model, "unaligned 32-bit crossing block");
    check(writer.snapshot().bit_cursor == 63 && writer.snapshot().data[3] == 0xff &&
          (writer.snapshot().data[7] & 0x80) == 0,
          "31/32-bit edge payload changed");
    const auto before = writer.snapshot();
    bool rejected = false;
    try { writer.write_bits(0, 0); }
    catch (const std::invalid_argument&) { rejected = true; }
    check(rejected && writer.snapshot() == before, "zero-count write changed state");
}

void crypt_ownership_and_repetition() {
    ResearchBitWriter20 writer;
    WordInterpreter model;
    writer.write_bits(0x12345678, 32);
    model.bits(0x12345678, 32);
    std::array<std::uint8_t, 3> key{0x12, 0x34, 0x56};
    const auto before = writer.snapshot();
    writer.crypt(key);
    model.crypt(key);
    same(writer, model, "first cyclic XOR");
    check(writer.snapshot().data[0] == static_cast<std::uint8_t>(before.data[0] ^ 0x12) &&
          writer.snapshot().data[3] == static_cast<std::uint8_t>(before.data[3] ^ 0x12) &&
          writer.snapshot().bit_cursor == 32, "cyclic XOR or cursor changed");
    key[0] = 0xff;
    check(writer.snapshot() == model.snapshot(), "caller key mutation changed owned data");
    const std::array<std::uint8_t, 3> original_key{0x12, 0x34, 0x56};
    writer.crypt(original_key);
    model.crypt(original_key);
    same(writer, model, "second cyclic XOR");
    check(writer.snapshot() == before, "repeated XOR did not restore data");
    writer.crypt({});
    check(writer.snapshot() == before, "empty key changed writer");
}

void crypt_key_space() {
    for (unsigned byte = 0; byte < 256; ++byte) {
        ResearchBitWriter20 writer;
        WordInterpreter model;
        writer.write_bits(0x87654321, 32);
        model.bits(0x87654321, 32);
        const auto before = writer.snapshot();
        const std::array<std::uint8_t, 1> key{static_cast<std::uint8_t>(byte)};
        writer.crypt(key);
        model.crypt(key);
        same(writer, model, "single-byte key space");
        for (std::size_t i = 0; i < before.data.size(); ++i) {
            check(writer.snapshot().data[i] ==
                  static_cast<std::uint8_t>(before.data[i] ^ key[0]),
                  "one-byte key failed to XOR a data byte");
        }
        writer.crypt(key);
        check(writer.snapshot() == before, "second single-byte key did not undo XOR");
    }
    std::array<std::uint8_t, 41> key{};
    for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<std::uint8_t>(i * 17);
    constexpr std::array<std::size_t, 9> lengths{0, 1, 2, 3, 19, 20, 21, 40, 41};
    for (std::size_t count : lengths) {
        ResearchBitWriter20 writer;
        WordInterpreter model;
        writer.crypt(std::span(key.data(), count));
        model.crypt(std::span(key.data(), count));
        same(writer, model, "variable key length");
        if (count != 0) {
            for (std::size_t i = 0; i < writer.snapshot().data.size(); ++i) {
                check(writer.snapshot().data[i] == key[i % count],
                      "variable key did not repeat across all 20 data bytes");
            }
        }
        check(writer.snapshot().bit_cursor == 0 && !writer.is_overflowed(),
              "crypt changed bit cursor or overflow flag");
    }
}

void advance_to(ResearchBitWriter20& writer, WordInterpreter& model,
                unsigned target) {
    const std::array<std::uint8_t, 1> initial{0xa5};
    writer.crypt(initial);
    model.crypt(initial);
    while (model.cursor < target) {
        const unsigned count = (target - model.cursor) < 32 ?
            (target - model.cursor) : 32;
        writer.write_bits(0, count);
        model.bits(0, count);
    }
    same(writer, model, "prefilled cursor setup");
}

void exhaustive_block_windows() {
    unsigned cases = 0;
    for (unsigned cursor = 0; cursor <= 160; ++cursor) {
        for (unsigned count = 1; count <= 32; ++count) {
            const auto full = count == 32 ? 0xffffffffu : (1u << count) - 1u;
            for (std::uint32_t value : {0u, full, 0xa5a5a5a5u & full}) {
                ResearchBitWriter20 writer;
                WordInterpreter model;
                advance_to(writer, model, cursor);
                writer.write_bits(value, count);
                model.bits(value, count);
                same(writer, model, "every cursor/count/value block window");
                ++cases;
            }
        }
    }
    check(cases == 161 * 32 * 3, "block-window coverage count changed");
}

void coordinate_window_matrix() {
    const float step = 0.03125f;
    const float end = 16385.0f;
    const std::array<float, 22> values{
        0.0f, -0.0f,
        std::numeric_limits<float>::denorm_min(),
        -std::numeric_limits<float>::denorm_min(),
        std::nextafter(step, 0.0f), step,
        std::nextafter(step, 1.0f),
        std::nextafter(-step, 0.0f), -step,
        std::nextafter(-step, -1.0f),
        0.5f, -0.5f, 1.0f, -1.0f,
        std::nextafter(1.0f, 0.0f),
        std::nextafter(-1.0f, 0.0f),
        16384.0f, -16384.0f,
        16384.5f, -16384.5f,
        std::nextafter(end, 0.0f),
        -std::nextafter(end, 0.0f)
    };
    constexpr std::array<unsigned, 20> cursors{
        0, 1, 2, 29, 30, 31, 32, 64, 96, 128,
        137, 145, 149, 151, 152, 153, 155, 157, 159, 160};
    for (unsigned cursor : cursors) {
        for (float value : values) {
            ResearchBitWriter20 writer;
            WordInterpreter model;
            advance_to(writer, model, cursor);
            writer.write_coord(value);
            model.coord(value);
            same(writer, model, "coordinate value/cursor matrix");
        }
    }
}

void invalid_inputs_are_atomic() {
    ResearchBitWriter20 writer;
    const auto before = writer.snapshot();
    const auto rejects_bits = [&](std::uint32_t value, unsigned count) {
        bool rejected = false;
        try { writer.write_bits(value, count); }
        catch (const std::invalid_argument&) { rejected = true; }
        check(rejected && writer.snapshot() == before, "invalid write_bits mutated state");
    };
    rejects_bits(0, 0);
    rejects_bits(0, 33);
    rejects_bits(8, 3);
    const auto rejects_coord = [&](float value) {
        bool rejected = false;
        try { writer.write_coord(value); }
        catch (const std::invalid_argument&) { rejected = true; }
        check(rejected && writer.snapshot() == before, "invalid write_coord mutated state");
    };
    rejects_coord(std::numeric_limits<float>::quiet_NaN());
    rejects_coord(std::numeric_limits<float>::infinity());
    rejects_coord(-std::numeric_limits<float>::infinity());
    rejects_coord(16385.0f);
}

std::uint32_t next(std::uint32_t& state) {
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}

void deterministic_operation_trace() {
    ResearchBitWriter20 writer;
    WordInterpreter model;
    std::uint32_t seed = 0x53248a19;
    constexpr std::array<float, 10> coordinates{
        -16384.0f, -5.5f, -1.0f, -0.03125f, -0.0f,
        0.0f, 0.03125f, 0.5f, 7.96875f, 16384.0f};
    for (unsigned step = 0; step < 512; ++step) {
        const auto selector = next(seed) % 5;
        if (selector <= 2) {
            const auto count = 1u + next(seed) % 32u;
            const auto random = next(seed);
            const auto value = count == 32 ? random : random & ((1u << count) - 1u);
            writer.write_bits(value, count);
            model.bits(value, count);
        } else if (selector == 3) {
            const auto value = coordinates[next(seed) % coordinates.size()];
            writer.write_coord(value);
            model.coord(value);
        } else {
            const std::array<std::uint8_t, 5> key{
                static_cast<std::uint8_t>(next(seed)), static_cast<std::uint8_t>(next(seed)),
                static_cast<std::uint8_t>(next(seed)), static_cast<std::uint8_t>(next(seed)),
                static_cast<std::uint8_t>(next(seed))};
            const auto count = next(seed) % 6;
            writer.crypt(std::span(key.data(), count));
            model.crypt(std::span(key.data(), count));
        }
        same(writer, model, "operation trace step " + std::to_string(step));
    }
}
} // namespace

int main() {
    try {
        bit_order_and_word_crossing();
        capacity_clamp_does_not_signal_overflow();
        partial_coordinate_blocks();
        coordinate_encoding();
        fractional_end_and_float_boundaries();
        bit_count_edges();
        crypt_ownership_and_repetition();
        crypt_key_space();
        invalid_inputs_are_atomic();
        exhaustive_block_windows();
        coordinate_window_matrix();
        deterministic_operation_trace();
        std::cout << "bit_writer_tests: 15,456 block windows, 440 coordinate windows, "
                     "512 trace steps, and boundary cases passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "bit_writer_tests: " << error.what() << '\n';
        return 1;
    }
}
