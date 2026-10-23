#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace fc {

// Source-owned reconstruction of the selected VoiceData message fields.
// No engine object, native pointer, or transport behavior.
struct ResearchVoiceMessage20 {
    static constexpr std::uint32_t presence_bits = 0x3e;
    static constexpr bool data_present = false;
    static constexpr std::int32_t format = 0;

    std::uint64_t xuid{};
    std::int32_t sequence_bytes{};
    std::uint32_t section_number{};
    std::uint32_t uncompressed_sample_offset{};

    bool operator==(const ResearchVoiceMessage20&) const = default;
};

struct VoiceMessage20WireBody {
    static constexpr std::size_t max_size = 34;

    std::array<std::uint8_t, max_size> bytes{};
    std::size_t size{};

    std::span<const std::uint8_t> view() const noexcept {
        return {bytes.data(), size <= max_size ? size : max_size};
    }
};

// Byte-aligned CNetMessagePB<CCLCMsg_VoiceData> message frame: type ID,
// protobuf body byte count, then the body. This is not a channel packet.
struct VoiceMessage20WireFrame {
    static constexpr std::uint32_t message_type = 10;
    static constexpr std::size_t max_size = 2 + VoiceMessage20WireBody::max_size;

    std::array<std::uint8_t, max_size> bytes{};
    std::size_t size{};

    std::span<const std::uint8_t> view() const noexcept {
        return {bytes.data(), size <= max_size ? size : max_size};
    }
};

ResearchVoiceMessage20 project_voice_message20(
    std::span<const std::uint8_t, 20> payload) noexcept;

VoiceMessage20WireBody serialize_voice_message20(
    std::span<const std::uint8_t, 20> payload) noexcept;

VoiceMessage20WireFrame serialize_voice_message20_frame(
    std::span<const std::uint8_t, 20> payload) noexcept;

} // namespace fc
