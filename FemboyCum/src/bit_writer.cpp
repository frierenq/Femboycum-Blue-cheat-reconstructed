#include "fc/bit_writer.hpp"

#include <array>
#include <cmath>
#include <limits>
#include <stdexcept>

namespace fc {

namespace {
void set_bit(std::array<std::uint8_t, ResearchBitWriter20::byte_capacity>& data,
             std::uint32_t cursor, bool bit) noexcept {
    auto& byte = data[cursor / 8];
    const auto mask = static_cast<std::uint8_t>(1u << (cursor & 7u));
    byte = static_cast<std::uint8_t>(bit ? (byte | mask) : (byte & ~mask));
}
} // namespace

void ResearchBitWriter20::write_block(std::uint32_t value, unsigned count) noexcept {
    if (bit_cursor_ + count > bit_capacity) {
        bit_cursor_ = bit_capacity;
        return;
    }
    for (unsigned index = 0; index < count; ++index) {
        set_bit(data_, bit_cursor_ + index, ((value >> index) & 1u) != 0);
    }
    bit_cursor_ += count;
}

void ResearchBitWriter20::write_one(bool bit) noexcept {
    if (bit_cursor_ >= bit_capacity) {
        overflow_ = true;
        return;
    }
    if (overflow_) return;
    set_bit(data_, bit_cursor_, bit);
    ++bit_cursor_;
}

void ResearchBitWriter20::write_bits(std::uint32_t value, unsigned count) {
    if (count == 0 || count > 32 || (count < 32 && (value >> count) != 0)) {
        throw std::invalid_argument("write_bits requires 1..32 bits and a fitting value");
    }
    write_block(value, count);
}

void ResearchBitWriter20::write_coord(float value) {
    if (!std::isfinite(value) || std::fabs(value) >= 16385.0f) {
        throw std::invalid_argument("write_coord requires a finite 14-bit integer part");
    }

    const auto integer = static_cast<std::uint32_t>(std::fabs(value));
    const auto scaled = static_cast<std::int32_t>(value * 32.0f);
    const auto magnitude = scaled < 0 ? -scaled : scaled;
    const auto fraction = static_cast<std::uint32_t>(magnitude) & 31u;

    write_one(integer != 0);
    write_one(fraction != 0);
    if (integer == 0 && fraction == 0) return;
    write_one(value <= -1.0f / 32.0f);
    if (integer != 0) write_block(integer - 1u, 14);
    if (fraction != 0) write_block(fraction, 5);
}

void ResearchBitWriter20::crypt(std::span<const std::uint8_t> key) {
    if (key.size() > static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) {
        throw std::length_error("crypt key length exceeds the selected signed input domain");
    }
    if (key.empty()) return;

    std::array<std::uint8_t, byte_capacity> repeated{};
    for (std::size_t index = 0; index < byte_capacity; ++index) {
        repeated[index] = key[index % key.size()];
    }
    for (std::size_t index = 0; index < byte_capacity; ++index) {
        data_[index] ^= repeated[index];
    }
}

} // namespace fc
