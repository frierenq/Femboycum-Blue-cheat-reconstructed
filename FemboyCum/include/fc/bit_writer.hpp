#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace fc {

struct BitWriter20Snapshot {
    std::array<std::uint8_t, 20> data{};
    std::uint32_t bit_cursor{};
    bool overflow{};

    bool operator==(const BitWriter20Snapshot&) const = default;
};

// Owned, bounded reconstruction of selected native bf_write effects.
// This is research-only: no native pointer, Lua binding, or engine ABI.
class ResearchBitWriter20 final {
public:
    static constexpr std::size_t byte_capacity = 20;
    static constexpr std::uint32_t bit_capacity = 160;

    void write_bits(std::uint32_t value, unsigned count);
    void write_coord(float value);
    void crypt(std::span<const std::uint8_t> key);

    bool is_overflowed() const noexcept { return overflow_; }
    BitWriter20Snapshot snapshot() const noexcept { return {data_, bit_cursor_, overflow_}; }

private:
    void write_one(bool bit) noexcept;
    void write_block(std::uint32_t value, unsigned count) noexcept;

    std::array<std::uint8_t, byte_capacity> data_{};
    std::uint32_t bit_cursor_{};
    bool overflow_{};
};

} // namespace fc
