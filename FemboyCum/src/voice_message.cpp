#include "fc/voice_message.hpp"

#include <bit>
#include <cstdint>
#include <exception>

namespace fc {
namespace {

std::uint32_t word_at(std::span<const std::uint8_t, 20> payload,
                      std::size_t index) noexcept {
    const auto start = index * 4;
    return static_cast<std::uint32_t>(payload[start]) |
           (static_cast<std::uint32_t>(payload[start + 1]) << 8) |
           (static_cast<std::uint32_t>(payload[start + 2]) << 16) |
           (static_cast<std::uint32_t>(payload[start + 3]) << 24);
}

void append(VoiceMessage20WireBody& body, std::uint8_t byte) noexcept {
    if (body.size >= body.max_size) std::terminate();
    body.bytes[body.size++] = byte;
}

void append_varint(VoiceMessage20WireBody& body, std::uint64_t value) noexcept {
    while (value >= 0x80) {
        append(body, static_cast<std::uint8_t>((value & 0x7f) | 0x80));
        value >>= 7;
    }
    append(body, static_cast<std::uint8_t>(value));
}

} // namespace

ResearchVoiceMessage20 project_voice_message20(
    std::span<const std::uint8_t, 20> payload) noexcept {
    const auto word0 = word_at(payload, 0);
    const auto word1 = word_at(payload, 1);
    const auto word2 = word_at(payload, 2);
    const auto word3 = word_at(payload, 3);
    const auto word4 = word_at(payload, 4);
    return {
        static_cast<std::uint64_t>(word3) |
            (static_cast<std::uint64_t>(word4) << 32),
        std::bit_cast<std::int32_t>(word1),
        word0,
        word2,
    };
}

VoiceMessage20WireBody serialize_voice_message20(
    std::span<const std::uint8_t, 20> payload) noexcept {
    const auto message = project_voice_message20(payload);
    VoiceMessage20WireBody body;

    append(body, 0x11); // xuid: field 2, fixed64
    for (unsigned shift = 0; shift < 64; shift += 8) {
        append(body, static_cast<std::uint8_t>(message.xuid >> shift));
    }
    append(body, 0x18); // format: field 3, enum
    append_varint(body, static_cast<std::uint32_t>(message.format));
    append(body, 0x20); // sequence_bytes: field 4, int32
    append_varint(body, static_cast<std::uint64_t>(
                            static_cast<std::int64_t>(message.sequence_bytes)));
    append(body, 0x28); // section_number: field 5, uint32
    append_varint(body, message.section_number);
    append(body, 0x30); // uncompressed_sample_offset: field 6, uint32
    append_varint(body, message.uncompressed_sample_offset);

    return body;
}

VoiceMessage20WireFrame serialize_voice_message20_frame(
    std::span<const std::uint8_t, 20> payload) noexcept {
    const auto body = serialize_voice_message20(payload);
    VoiceMessage20WireFrame frame;
    // On the selected route, type 10 and all supported body lengths (<=34)
    // each fit one base-128 varint byte.
    frame.bytes[0] = static_cast<std::uint8_t>(frame.message_type);
    frame.bytes[1] = static_cast<std::uint8_t>(body.size);
    for (std::size_t index = 0; index < body.size; ++index) {
        frame.bytes[index + 2] = body.bytes[index];
    }
    frame.size = body.size + 2;
    return frame;
}

} // namespace fc
