#pragma once
#include <algorithm>
#include <cstdint>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace femboylose::recovered {
using ChoiceValue=std::variant<std::monostate,bool,std::int64_t,std::string>;
// Only the checked default branch of 4202c656. Locale-specific comparison is open.
inline bool ascii_choice_equal(const std::string& a,const std::string& b) {
    for(std::size_t n=0;;++n) {
        auto x=n<a.size()?static_cast<unsigned char>(a[n]):0u;
        auto y=n<b.size()?static_cast<unsigned char>(b[n]):0u;
        if(x>='A' && x<='Z') x+='a'-'A';
        if(y>='A' && y<='Z') y+='a'-'A';
        if(x!=y) return false;
        if(x==0) return true;
    }
}
inline std::optional<std::size_t> first_choice(const std::vector<std::string>& options,
                                             const std::string& query) {
    for(std::size_t n=0;n<options.size();++n)
        if(ascii_choice_equal(options[n],query)) return n;
    return std::nullopt;
}

// Semantic projection with externally supplied, already materialized labels.
// Original hashing/localization, Lua refs, ABI, history and graphics are not hosted.
class ComboState {
public:
    using Notify=std::function<void()>;
    explicit ComboState(std::vector<std::string> labels,std::int32_t initial=0,Notify notify={},
                        std::uint32_t script_context=0)
        :labels_(std::move(labels)),stored_(initial),notify_(std::move(notify)),script_context_(script_context) {}
    std::int32_t stored_index() const noexcept{return stored_;}
    bool active() const noexcept{return active_;}
    std::uint32_t owner() const noexcept{return owner_;}
    std::optional<std::int32_t> override_index() const noexcept {
        return active_?std::optional<std::int32_t>{override_}:std::nullopt;
    }
    // 412e4610: invalid indices produce empty text;get itself does not clamp.
    std::string label_at(std::int32_t index) const {
        return index<0 || static_cast<std::size_t>(index)>=labels_.size()?std::string{}:labels_[static_cast<std::size_t>(index)];
    }
    std::string stored_label() const{return label_at(stored_);}
    std::optional<std::string> override_label() const {
        return active_?std::optional<std::string>{label_at(override_)}:std::nullopt;
    }
    // 412c0d70: conversion and search precede mutation. Missing label is a no-op.
    bool write_label(const ChoiceValue& value,bool as_override=false,std::uint32_t owner=0) {
        const auto* text=std::get_if<std::string>(&value);
        if(!text) throw std::invalid_argument("combo requires Lua string type 4");
        const auto index=first_choice(labels_,*text);
        if(!index) return false;
        active_=false;
        if(as_override){override_=static_cast<std::int32_t>(*index);active_=true;owner_=owner;}
        else {stored_=static_cast<std::int32_t>(*index);if(notify_)notify_();}
        return true;
    }
    // 41bac9f0: selected GUI path writes stored index only when list nonempty.
    void normalize_stored_for_draw() {
        if(!labels_.empty()) stored_=std::clamp(stored_,0,static_cast<std::int32_t>(labels_.size()-1));
    }
    // 41a76b70 direct choice-base branch: owner-context gate,then replace ID vector.
    // The model receives labels already resolved externally. No index remapping.
    bool replace_labels_for_context(std::vector<std::string> next,std::uint32_t context) {
        if(context!=script_context_)return false;
        labels_=std::move(next);return true;
    }
private:
    std::vector<std::string> labels_;
    std::int32_t stored_=0,override_=0;
    bool active_=false;
    std::uint32_t owner_=0;
    Notify notify_;
    std::uint32_t script_context_=0;
};

struct SelectableFields {std::uint32_t stored=0,override_mask=0,owner=0;bool active=false;};
class SelectableState {
public:
    using BeforeWrite=std::function<void(SelectableFields&)>;
    using Notify=std::function<void()>;
    explicit SelectableState(std::vector<std::string> labels,std::uint32_t initial=0,
                             BeforeWrite before={},Notify notify={},std::uint32_t script_context=0)
        :labels_(std::move(labels)),before_(std::move(before)),notify_(std::move(notify)),script_context_(script_context) {fields_.stored=initial;}
    const SelectableFields& fields() const noexcept{return fields_;}
    // Register BT/SHL semantics, not unbounded C++ shift or choice-count validation.
    static std::uint32_t bit(std::size_t zero_based) noexcept {
        return std::uint32_t{1}<<(zero_based&31u);
    }
    bool contains_one_based(std::int32_t index,bool override_mode=false) const noexcept {
        if(override_mode && !fields_.active)return false;
        const auto mask=override_mode?fields_.override_mask:fields_.stored;
        const auto zero_based=static_cast<std::uint32_t>(index)-1u;
        return (mask&bit(zero_based))!=0;
    }
    bool contains_label(const std::string& label,bool override_mode=false) const {
        if(override_mode && !fields_.active)return false;
        const auto index=first_choice(labels_,label);
        const auto mask=override_mode?fields_.override_mask:fields_.stored;
        return index && (mask&bit(*index))!=0;
    }
    std::vector<std::string> selected_labels(bool override_mode=false) const {
        if(override_mode && !fields_.active)return {};
        std::vector<std::string> result;
        const auto mask=override_mode?fields_.override_mask:fields_.stored;
        for(std::size_t n=0;n<labels_.size();++n)if(mask&bit(n))result.push_back(labels_[n]);
        return result;
    }
    bool replace_labels_for_context(std::vector<std::string> next,std::uint32_t context) {
        if(context!=script_context_)return false;
        labels_=std::move(next);return true;
    }
    // 41bb1be0 valid string-varargs branch;not the Lua table/iterator branch.
    // before_ stands in for virtual+74,whose history effects are a separate contract.
    // No public Lua signature is implied for the helper's empty-range edge case.
    void native_write_labels(const std::vector<ChoiceValue>& values,bool as_override=false,
                             std::uint32_t owner=0) {
        if(before_)before_(fields_);
        fields_.active=false;
        if(as_override){fields_.active=true;fields_.override_mask=0;fields_.owner=owner;}
        else fields_.stored=0;
        if(values.empty())fields_.stored=0; // native empty-range branch, even override mode
        for(const auto& value:values){
            const auto* text=std::get_if<std::string>(&value);
            if(!text)throw std::invalid_argument("selectable varargs require Lua strings");
            if(const auto index=first_choice(labels_,*text)){
                if(as_override)fields_.override_mask|=bit(*index);
                else fields_.stored|=bit(*index);
            }
        }
        if(!as_override && notify_)notify_();
    }
private:
    std::vector<std::string> labels_;
    SelectableFields fields_;
    BeforeWrite before_;
    Notify notify_;
    std::uint32_t script_context_=0;
};
}
