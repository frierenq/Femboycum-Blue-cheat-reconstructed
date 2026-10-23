#pragma once
#include <cstdint>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>

namespace femboylose::recovered {
// Analyst-authored semantic projection of the selected FemboyLose nl.bin paths.
// This is not the original ABI, Lua runtime, complete configuration or widget.
class TextSetting {
public:
    using Value = std::variant<std::monostate, bool, std::int64_t, std::string>;
    using Boundary = std::function<void()>;
    explicit TextSetting(std::string initial, Boundary notify = {},
                         Boundary related78 = {}, Boundary related74 = {})
        : stored_(initial), initial_(std::move(initial)), notify_(std::move(notify)),
          related78_(std::move(related78)), related74_(std::move(related74)) {}

    const std::string& stored() const noexcept { return stored_; }
    const std::string& initial() const noexcept { return initial_; }
    const std::optional<std::string>& override_value() const noexcept { return override_; }
    // Internal field selection only, not a claim about the slot+94 return ABI.
    const std::string& effective_fields() const noexcept {
        return override_ ? *override_ : stored_;
    }
    std::uint32_t owner_token() const noexcept { return owner_; }

    // 41a78770 clears the previous override before either strict conversion.
    // Lua type==4 is required: number/Boolean/nil do not become text here.
    void write(const Value& value, bool as_override = false, std::uint32_t owner = 0) {
        clear_override();
        const auto* text = std::get_if<std::string>(&value);
        if (!text) throw std::invalid_argument("native writer requires Lua string type 4");
        if (as_override) { override_ = *text; owner_ = owner; }
        else { stored_ = *text; notify_boundary(); }
    }
    // 41aad000: reset the optional string;the owner field itself is not zeroed.
    void clear_override() noexcept { override_.reset(); }
    // 41aca2b0: equal token dispatches virtual+a4, even for token zero.
    void clear_for_owner(std::uint32_t owner) noexcept {
        if (owner_ == owner) clear_override();
    }
    // 41af4260: this query has the side effect of removing an equal override.
    bool retain_distinct_override() {
        if (override_ && *override_ != stored_) return true;
        clear_override();
        return false;
    }
    // 41accd10: copy initial,clear override,related+78,related+74,virtual+40.
    // Boundary callbacks stand in for native virtual dispatch;timing is not emulated.
    void reset() {
        stored_ = initial_;
        clear_override();
        if (related78_) related78_();
        if (related74_) related74_();
        notify_boundary();
    }
    // 41aa0c40 virtual+a8 captures the current stored value as the new default.
    void capture_default() { initial_ = stored_; }
    // 41a98690: string JSON tag3 and stored+bc under decimal key0x108d5742.
    // A semantic pair only, not a complete original configuration document.
    std::pair<std::string, std::string> export_value_leaf() const {
        return {std::to_string(0x108d5742u), stored_};
    }
    // Prefix only: 41ac8620 clears override,then41a78450 reads optional string.
    // Missing value preserves stored. Native history/base import is not modeled.
    void import_value_prefix(const std::optional<Value>& field) {
        clear_override();
        if (!field) return;
        const auto* text = std::get_if<std::string>(&*field);
        if (!text) throw std::invalid_argument("native JSON string conversion requires tag 3");
        stored_ = *text;
    }
private:
    void notify_boundary() {
        // 41a92cd0 also clears any active override before processing history.
        clear_override();
        if (notify_) notify_();
    }
    std::string stored_;
    std::string initial_;
    std::optional<std::string> override_;
    std::uint32_t owner_ = 0;
    Boundary notify_, related78_, related74_;
};
}
