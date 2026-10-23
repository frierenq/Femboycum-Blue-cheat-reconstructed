#include "fc/voice_message.hpp"

#include <array>
#include <cstdint>
#include <initializer_list>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <vector>

namespace {

void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

std::array<std::uint8_t, 20> payload(std::array<std::uint32_t, 5> words) {
    std::array<std::uint8_t, 20> result{};
    for (std::size_t i = 0; i < words.size(); ++i) {
        for (unsigned shift = 0; shift < 32; shift += 8) {
            result[i * 4 + shift / 8] =
                static_cast<std::uint8_t>(words[i] >> shift);
        }
    }
    return result;
}

void equal_wire(const fc::VoiceMessage20WireBody& actual,
                std::initializer_list<std::uint8_t> expected,
                const char* label) {
    check(actual.size == expected.size(), label);
    auto iter = expected.begin();
    for (std::size_t i = 0; i < actual.size; ++i, ++iter) {
        check(actual.bytes[i] == *iter, label);
    }
    for (std::size_t i = actual.size; i < actual.bytes.size(); ++i) {
        check(actual.bytes[i] == 0, "unused tail is not zero");
    }
}

void equal_frame(const fc::VoiceMessage20WireFrame& actual,
                 std::initializer_list<std::uint8_t> expected,
                 const char* label) {
    check(actual.size == expected.size(), label);
    auto iter = expected.begin();
    for (std::size_t i = 0; i < actual.size; ++i, ++iter) {
        check(actual.bytes[i] == *iter, label);
    }
    for (std::size_t i = actual.size; i < actual.bytes.size(); ++i) {
        check(actual.bytes[i] == 0, "unused frame tail is not zero");
    }
}

std::uint64_t read_varint(std::span<const std::uint8_t> bytes,
                         std::size_t& cursor) {
    std::uint64_t value = 0;
    for (unsigned shift = 0; shift < 70; shift += 7) {
        check(cursor < bytes.size(), "truncated varint");
        const auto byte = bytes[cursor++];
        value |= static_cast<std::uint64_t>(byte & 0x7f) << shift;
        if ((byte & 0x80) == 0) return value;
    }
    throw std::runtime_error("oversized varint");
}

void parse_body_and_check(std::span<const std::uint8_t> body,
                          const fc::ResearchVoiceMessage20& fields) {
    std::size_t cursor = 0;
    check(body[cursor++] == 0x11, "missing fixed64 field 2");
    std::uint64_t xuid = 0;
    for (unsigned shift = 0; shift < 64; shift += 8) {
        check(cursor < body.size(), "truncated fixed64");
        xuid |= static_cast<std::uint64_t>(body[cursor++]) << shift;
    }
    check(xuid == fields.xuid, "fixed64 field mismatch");
    check(cursor < body.size() && body[cursor++] == 0x18,
          "missing enum field 3");
    check(read_varint(body, cursor) == 0, "format is not present-zero");
    check(cursor < body.size() && body[cursor++] == 0x20,
          "missing int32 field 4");
    const auto sequence = read_varint(body, cursor);
    const auto sign_extended = static_cast<std::uint64_t>(
        static_cast<std::int64_t>(fields.sequence_bytes));
    check(sequence == sign_extended, "signed int32 varint mismatch");
    check(cursor < body.size() && body[cursor++] == 0x28,
          "missing uint32 field 5");
    check(read_varint(body, cursor) == fields.section_number,
          "section number mismatch");
    check(cursor < body.size() && body[cursor++] == 0x30,
          "missing uint32 field 6");
    check(read_varint(body, cursor) == fields.uncompressed_sample_offset,
          "sample offset mismatch");
    check(cursor == body.size(), "extra fields or trailing bytes");
}

void golden_boundaries() {
    static_assert(fc::ResearchVoiceMessage20::presence_bits == 0x3e);
    static_assert(!fc::ResearchVoiceMessage20::data_present);
    static_assert(fc::ResearchVoiceMessage20::format == 0);
    static_assert(fc::VoiceMessage20WireBody::max_size == 34);
    static_assert(fc::VoiceMessage20WireFrame::message_type == 10);
    static_assert(fc::VoiceMessage20WireFrame::max_size == 36);

    const auto zero = payload({0, 0, 0, 0, 0});
    const auto zero_fields = fc::project_voice_message20(zero);
    check(zero_fields.xuid == 0 && zero_fields.sequence_bytes == 0 &&
          zero_fields.section_number == 0 &&
          zero_fields.uncompressed_sample_offset == 0, "zero projection");
    equal_wire(fc::serialize_voice_message20(zero), {
        0x11, 0, 0, 0, 0, 0, 0, 0, 0,
        0x18, 0, 0x20, 0, 0x28, 0, 0x30, 0,
    }, "present-zero fields");
    equal_frame(fc::serialize_voice_message20_frame(zero), {
        0x0a, 0x11,
        0x11, 0, 0, 0, 0, 0, 0, 0, 0,
        0x18, 0, 0x20, 0, 0x28, 0, 0x30, 0,
    }, "present-zero framed golden");

    const auto asymmetric = payload({0x11223344u, 0x7fu, 0x80u,
                                     0x55667788u, 0x99aabbccu});
    const auto asymmetric_fields = fc::project_voice_message20(asymmetric);
    check(asymmetric_fields.xuid == 0x99aabbcc55667788ull &&
          asymmetric_fields.sequence_bytes == 127 &&
          asymmetric_fields.section_number == 0x11223344u &&
          asymmetric_fields.uncompressed_sample_offset == 0x80u,
          "asymmetric word projection");
    equal_wire(fc::serialize_voice_message20(asymmetric), {
        0x11, 0x88, 0x77, 0x66, 0x55, 0xcc, 0xbb, 0xaa, 0x99,
        0x18, 0, 0x20, 0x7f,
        0x28, 0xc4, 0xe6, 0x88, 0x89, 0x01,
        0x30, 0x80, 0x01,
    }, "asymmetric descriptor-order golden");
    equal_frame(fc::serialize_voice_message20_frame(asymmetric), {
        0x0a, 0x16,
        0x11, 0x88, 0x77, 0x66, 0x55, 0xcc, 0xbb, 0xaa, 0x99,
        0x18, 0, 0x20, 0x7f,
        0x28, 0xc4, 0xe6, 0x88, 0x89, 0x01,
        0x30, 0x80, 0x01,
    }, "asymmetric framed golden");

    const auto all_ones = payload({0xffffffffu, 0xffffffffu, 0xffffffffu,
                                   0xffffffffu, 0xffffffffu});
    const auto all_ones_fields = fc::project_voice_message20(all_ones);
    check(all_ones_fields.xuid == 0xffffffffffffffffull &&
          all_ones_fields.sequence_bytes == -1 &&
          all_ones_fields.section_number == 0xffffffffu &&
          all_ones_fields.uncompressed_sample_offset == 0xffffffffu,
          "all-ones projection");
    equal_wire(fc::serialize_voice_message20(all_ones), {
        0x11, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x18, 0x00,
        0x20, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
        0x28, 0xff, 0xff, 0xff, 0xff, 0x0f,
        0x30, 0xff, 0xff, 0xff, 0xff, 0x0f,
    }, "maximal 34-byte body and negative int32");
    equal_frame(fc::serialize_voice_message20_frame(all_ones), {
        0x0a, 0x22,
        0x11, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x18, 0x00,
        0x20, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
        0x28, 0xff, 0xff, 0xff, 0xff, 0x0f,
        0x30, 0xff, 0xff, 0xff, 0xff, 0x0f,
    }, "maximal 36-byte framed golden");

    const auto sign_boundary = payload({1, 0x80000000u, 3, 4, 5});
    check(fc::project_voice_message20(sign_boundary).sequence_bytes ==
          std::numeric_limits<std::int32_t>::min(), "int32 sign boundary");
    equal_wire(fc::serialize_voice_message20(sign_boundary), {
        0x11, 4, 0, 0, 0, 5, 0, 0, 0,
        0x18, 0,
        0x20, 0x80, 0x80, 0x80, 0x80, 0xf8,
        0xff, 0xff, 0xff, 0xff, 0x01,
        0x28, 1, 0x30, 3,
    }, "INT_MIN sign-extended varint");
}

void owned_and_varied() {
    auto source = payload({1, 2, 3, 4, 5});
    const auto projection = fc::project_voice_message20(source);
    const auto wire = fc::serialize_voice_message20(source);
    const auto frame = fc::serialize_voice_message20_frame(source);
    source.fill(0xff);
    check(projection.xuid == 0x0000000500000004ull &&
          projection.section_number == 1, "projection borrowed source bytes");
    check(wire.bytes[1] == 4 && wire.bytes[5] == 5,
          "wire body borrowed source bytes");
    check(frame.bytes[0] == 10 && frame.bytes[3] == 4 &&
          frame.bytes[7] == 5, "frame borrowed source bytes");

    std::uint32_t state = 0x71c48b26u;
    for (unsigned sample = 0; sample < 2048; ++sample) {
        std::array<std::uint32_t, 5> words{};
        for (auto& word : words) {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            word = state;
        }
        const auto bytes = payload(words);
        const auto fields = fc::project_voice_message20(bytes);
        const auto body = fc::serialize_voice_message20(bytes);
        const auto framed = fc::serialize_voice_message20_frame(bytes);
        check(body.size <= body.max_size, "wire capacity exceeded");
        parse_body_and_check(body.view(), fields);
        check(framed.size == body.size + 2 &&
              framed.size <= framed.max_size, "frame capacity/length mismatch");
        std::size_t frame_cursor = 0;
        check(read_varint(framed.view(), frame_cursor) == 10,
              "framed type varint mismatch");
        check(read_varint(framed.view(), frame_cursor) == body.size,
              "framed length varint mismatch");
        check(frame_cursor + body.size == framed.size,
              "framed body boundary mismatch");
        parse_body_and_check(framed.view().subspan(frame_cursor), fields);
    }
}

} // namespace

int main() {
    try {
        golden_boundaries();
        owned_and_varied();
        std::cout << "voice-message projection, body and byte-aligned frame passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
