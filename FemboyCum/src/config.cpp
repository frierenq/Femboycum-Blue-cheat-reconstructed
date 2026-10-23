#include "fc/config.hpp"
#include <charconv>
#include <stdexcept>

namespace fc {
namespace {
std::size_t length(std::string_view text) {
    std::size_t result{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), result);
    if (text.empty() || error != std::errc{} || end != text.data() + text.size() ||
        result > ConfigDocument::max_bytes)
        throw std::invalid_argument("invalid config record length");
    return result;
}
}
ConfigDocument ConfigDocument::parse(std::string_view input) {
    ConfigDocument result;
    if (input.empty()) return result;
    if (input.size() > max_bytes || !input.starts_with("FCFG/1\n"))
        throw std::invalid_argument("expected experimental FCFG/1 document");
    input.remove_prefix(7);
    while (!input.empty()) {
        const auto line = input.find('\n');
        if (line == std::string_view::npos) throw std::invalid_argument("missing record header");
        const auto header = input.substr(0, line);
        const auto space = header.find(' ');
        if (space == std::string_view::npos) throw std::invalid_argument("invalid record header");
        const auto key_size = length(header.substr(0, space));
        const auto value_size = length(header.substr(space + 1));
        input.remove_prefix(line + 1);
        if (!key_size || key_size > input.size() || value_size >= input.size() - key_size ||
            input[key_size + value_size] != '\n')
            throw std::invalid_argument("truncated config record");
        std::string key(input.substr(0, key_size));
        std::string value(input.substr(key_size, value_size));
        if (!result.fields.emplace(std::move(key), std::move(value)).second)
            throw std::invalid_argument("duplicate config key");
        input.remove_prefix(key_size + value_size + 1);
    }
    return result;
}
std::string ConfigDocument::serialize() const {
    std::string result = "FCFG/1\n";
    for (const auto& [key, value] : fields) {
        if (key.empty() || key.size() > max_bytes || value.size() > max_bytes)
            throw std::invalid_argument("invalid config field size");
        result += std::to_string(key.size()) + " " + std::to_string(value.size()) + "\n";
        result += key;
        result += value;
        result += '\n';
        if (result.size() > max_bytes) throw std::length_error("config exceeds size limit");
    }
    return result;
}
}
