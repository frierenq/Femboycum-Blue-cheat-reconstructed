// Authored RNG only. Reads fixture actions from stdin; never loads a native DLL.
#include "fc/uniform_random.hpp"
#include <bit>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <xmmintrin.h>

namespace {
struct Action { char kind{}; unsigned arity{}; std::uint32_t args[3]{}; };
struct Row { Action action{}; std::uint32_t result{}; std::uint32_t mxcsr{};
             std::uint16_t x87_control{}; std::uint16_t x87_status{}; };

std::uint32_t word(const std::string& text) {
    const auto value = std::stoull(text, nullptr, 0);
    if (value > 0xffffffffULL) throw std::runtime_error("word outside u32");
    return static_cast<std::uint32_t>(value);
}
std::uint32_t signed_word(const std::string& text) {
    const auto value = std::stoll(text, nullptr, 0);
    if (value < INT32_MIN || value > INT32_MAX) throw std::runtime_error("word outside i32");
    return std::bit_cast<std::uint32_t>(static_cast<std::int32_t>(value));
}
std::vector<Action> read_actions() {
    std::vector<Action> result;
    std::string line;
    while (std::getline(std::cin, line)) {
        std::istringstream input(line);
        std::string tag, words[3], extra;
        if (!(input >> tag)) continue;
        if (tag.size() != 1) throw std::runtime_error("bad action tag");
        Action action{};
        action.kind = tag[0];
        const int arity = action.kind == 'M' ? 0 : action.kind == 'S' ? 1 :
                          action.kind == 'I' || action.kind == 'F' ? 2 :
                          action.kind == 'E' ? 3 : -1;
        if (arity < 0) throw std::runtime_error("unknown action");
        action.arity = static_cast<unsigned>(arity);
        for (int i = 0; i < arity; ++i) {
            if (!(input >> words[i])) throw std::runtime_error("missing argument");
            action.args[i] = action.kind == 'S' || action.kind == 'I' ?
                             signed_word(words[i]) : word(words[i]);
        }
        if (input >> extra) throw std::runtime_error("extra argument");
        result.push_back(action);
    }
    return result;
}
struct X87State { std::uint16_t control; std::uint16_t status; };
X87State read_x87() noexcept {
    std::uint16_t control = 0, status = 0;
#if defined(_M_IX86)
    __asm { fnstcw control }
    __asm { fnstsw status }
#endif
    return {control, status};
}
void select_mode() noexcept {
    _mm_setcsr(0x1f80u);
#if defined(_M_IX86)
    const std::uint16_t control = 0x027f;
    __asm { fnclex }
    __asm { fldcw control }
#endif
}
float f32(std::uint32_t bits) noexcept { return std::bit_cast<float>(bits); }
}

int main() {
    try {
        const auto actions = read_actions();
        fc::ProfileUniformRandom rng;
        std::vector<Row> rows;
        rows.reserve(actions.size());
        select_mode();
        for (const auto& action : actions) {
            std::uint32_t value = 0;
            switch (action.kind) {
            case 'M': break;
            case 'S': rng.seed(std::bit_cast<std::int32_t>(action.args[0])); break;
            case 'I': value = std::bit_cast<std::uint32_t>(rng.integer(
                std::bit_cast<std::int32_t>(action.args[0]),
                std::bit_cast<std::int32_t>(action.args[1]))); break;
            case 'F': value = std::bit_cast<std::uint32_t>(rng.real(
                f32(action.args[0]), f32(action.args[1]))); break;
            case 'E': value = std::bit_cast<std::uint32_t>(rng.real_exp(
                f32(action.args[0]), f32(action.args[1]), f32(action.args[2]))); break;
            default: throw std::runtime_error("unreachable action");
            }
            const auto mxcsr = static_cast<std::uint32_t>(_mm_getcsr());
            const auto x87 = read_x87();
            rows.push_back(Row{action, value, mxcsr, x87.control, x87.status});
        }
        for (std::size_t i = 0; i < rows.size(); ++i)
            std::printf("%zu %c %u %08x %08x %08x %08x %08x %04x %04x\n",
                        i, rows[i].action.kind, rows[i].action.arity,
                        rows[i].action.args[0], rows[i].action.args[1],
                        rows[i].action.args[2], rows[i].result, rows[i].mxcsr,
                        rows[i].x87_control, rows[i].x87_status);
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "owned FP probe: %s\n", error.what());
        return 1;
    }
}
