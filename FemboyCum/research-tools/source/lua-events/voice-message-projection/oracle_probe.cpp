// Authored source-only voice-message probe; contains no original code.
#include "fc/voice_message.hpp"

#include <array>
#include <cstdint>
#include <iostream>
#include <string>

namespace {

int nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

char hex_digit(unsigned value) {
    return "0123456789abcdef"[value & 15];
}

} // namespace

int main() {
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.size() != 40) return 2;
        std::array<std::uint8_t, 20> payload{};
        for (std::size_t i = 0; i < payload.size(); ++i) {
            const int high = nibble(line[i * 2]);
            const int low = nibble(line[i * 2 + 1]);
            if (high < 0 || low < 0) return 2;
            payload[i] = static_cast<std::uint8_t>((high << 4) | low);
        }
        const auto body = fc::serialize_voice_message20(payload);
        for (const auto byte : body.view()) {
            std::cout.put(hex_digit(byte >> 4));
            std::cout.put(hex_digit(byte));
        }
        std::cout.put('\n');
    }
    return std::cin.bad() ? 2 : 0;
}
