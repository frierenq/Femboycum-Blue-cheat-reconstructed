#pragma once
#include <map>
#include <string>
#include <string_view>

namespace fc {
// An experimental lossless envelope, NOT the historical native config format.
// Unknown records are retained byte-for-byte in their keys and values.
class ConfigDocument {
public:
    static constexpr std::size_t max_bytes = 1024 * 1024;
    static ConfigDocument parse(std::string_view input);
    std::string serialize() const;
    std::map<std::string, std::string> fields;
};
}
