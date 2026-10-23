#include "fc/hook_transactions.hpp"

#include <algorithm>
#include <exception>
#include <stdexcept>

namespace fc {
namespace {
bool valid_role(HookRole role) noexcept {
    return role == HookRole::Feedback || role == HookRole::ResetCallback;
}
}

HookTransactions::~HookTransactions() noexcept {
    // A live or indeterminate backend may still retain &slot.target_word.
    // Never let a continuing process silently free that storage.
    if (!active_.empty() || !retained_.empty() || poisoned_) std::terminate();
}

void HookTransactions::release(std::vector<Record>& records) noexcept {
    for (const auto& record : records) backend_.release_slot(*record.slot);
    records.clear();
}

HookStatus HookTransactions::install(const std::vector<HookSpec>& specs) {
    if (poisoned_) return HookStatus::Poisoned;
    if (specs.empty()) return HookStatus::NoChange;
    if (specs.size() > max_hooks - active_.size()) return HookStatus::CapacityExceeded;
    for (std::size_t i = 0; i < specs.size(); ++i) {
        const auto& spec = specs[i];
        if (!valid_role(spec.role) || !spec.target || !spec.replacement)
            return HookStatus::InvalidSpec;
        if (std::any_of(active_.begin(), active_.end(), [&](const Record& r) { return r.role == spec.role; }))
            return HookStatus::DuplicateRole;
        for (std::size_t j = 0; j < i; ++j)
            if (specs[j].role == spec.role) return HookStatus::DuplicateRole;
    }

    // Every allocation happens before begin. Slot objects remain at stable
    // addresses even if these record vectors grow or move.
    active_.reserve(active_.size() + specs.size());
    retained_.reserve(retained_.size() + specs.size());
    std::vector<Record> staged;
    staged.reserve(specs.size());
    try {
        for (const auto& spec : specs)
            staged.push_back({spec.role, spec.replacement, &backend_.reserve_slot(spec.target)});
    } catch (...) {
        release(staged);
        throw;
    }
    const auto begin = backend_.begin();
    if (begin == HookBegin::Uncertain) {
        poisoned_ = true;
        retained_.insert(retained_.end(), staged.begin(), staged.end());
        staged.clear();
        return HookStatus::Uncertain;
    }
    if (begin == HookBegin::Rejected) {
        release(staged);
        return HookStatus::BeginRejected;
    }
    if (begin != HookBegin::Ready) std::terminate();
    for (const auto& record : staged) {
        if (backend_.attach(*record.slot, record.replacement)) continue;
        if (!backend_.abort()) {
            poisoned_ = true;
            retained_.insert(retained_.end(), staged.begin(), staged.end());
            staged.clear();
            return HookStatus::Uncertain;
        }
        release(staged);
        return HookStatus::OperationRejected;
    }
    switch (backend_.commit()) {
    case HookCommit::Applied:
        active_.insert(active_.end(), staged.begin(), staged.end());
        staged.clear();
        return HookStatus::Applied;
    case HookCommit::Reverted:
        release(staged);
        return HookStatus::CommitReverted;
    case HookCommit::Uncertain:
        poisoned_ = true;
        retained_.insert(retained_.end(), staged.begin(), staged.end());
        staged.clear();
        return HookStatus::Uncertain;
    }
    std::terminate();
}

HookStatus HookTransactions::detach_all() noexcept {
    if (poisoned_) return HookStatus::Poisoned;
    if (active_.empty()) return HookStatus::NoChange;
    const auto begin = backend_.begin();
    if (begin == HookBegin::Uncertain) {
        poisoned_ = true;
        return HookStatus::Uncertain;
    }
    if (begin == HookBegin::Rejected) return HookStatus::BeginRejected;
    if (begin != HookBegin::Ready) std::terminate();
    for (auto it = active_.rbegin(); it != active_.rend(); ++it) {
        if (backend_.detach(*it->slot, it->replacement)) continue;
        if (!backend_.abort()) {
            poisoned_ = true;
            return HookStatus::Uncertain;
        }
        return HookStatus::OperationRejected;
    }
    switch (backend_.commit()) {
    case HookCommit::Applied:
        release(active_);
        return HookStatus::Applied;
    case HookCommit::Reverted:
        return HookStatus::CommitReverted;
    case HookCommit::Uncertain:
        poisoned_ = true;
        return HookStatus::Uncertain;
    }
    std::terminate();
}

std::optional<HookSnapshot> HookTransactions::snapshot(HookRole role) const noexcept {
    for (const auto& record : active_) {
        if (record.role == role) {
            const auto& slot = *record.slot;
            return HookSnapshot{role, slot.original, slot.target_word, slot.trampoline_word,
                                reinterpret_cast<std::uintptr_t>(&slot.target_word)};
        }
    }
    return std::nullopt;
}

HookSlot& MockDeferredHookBackend::reserve_slot(HookEndpoint target) {
    auto slot = std::make_unique<HookSlot>(target);
    auto& result = *slot;
    slots_.push_back(std::move(slot));
    return result;
}

void MockDeferredHookBackend::release_slot(HookSlot& slot) noexcept {
    for (std::size_t i = 0; i < pending_count_; ++i)
        if (pending_[i].target_word == &slot.target_word) std::terminate();
    const auto it = std::find_if(slots_.begin(), slots_.end(),
        [&slot](const auto& item) { return item.get() == &slot; });
    if (it == slots_.end()) std::terminate();
    slots_.erase(it);
}

HookBegin MockDeferredHookBackend::begin() noexcept {
    if (transaction_open_) return HookBegin::Uncertain;
    if (reject_begin_) { reject_begin_ = false; return HookBegin::Rejected; }
    transaction_open_ = true;
    pending_count_ = 0;
    attach_calls_ = 0;
    detach_calls_ = 0;
    return HookBegin::Ready;
}

bool MockDeferredHookBackend::attach(HookSlot& slot, HookEndpoint replacement) noexcept {
    if (!transaction_open_ || !replacement || pending_count_ == pending_.size()) return false;
    ++attach_calls_;
    if (reject_attach_at_ == attach_calls_) { reject_attach_at_ = 0; return false; }
    // Match the relevant DetourAttachEx timing: optional output is written
    // now, while ppPointer (&target_word) is retained for commit.
    slot.trampoline_word = next_trampoline_++;
    pending_[pending_count_++] = Pending{&slot.target_word, slot.trampoline_word};
    return true;
}

bool MockDeferredHookBackend::detach(HookSlot& slot, HookEndpoint replacement) noexcept {
    if (!transaction_open_ || !replacement || pending_count_ == pending_.size()) return false;
    ++detach_calls_;
    if (reject_detach_at_ == detach_calls_) { reject_detach_at_ = 0; return false; }
    pending_[pending_count_++] = Pending{&slot.target_word, slot.original};
    return true;
}

HookCommit MockDeferredHookBackend::commit() noexcept {
    if (!transaction_open_) return HookCommit::Uncertain;
    transaction_open_ = false;
    if (revert_commit_) {
        revert_commit_ = false;
        pending_count_ = 0;
        last_commit_write_count_ = 0;
        return HookCommit::Reverted;
    }
    last_commit_write_count_ = pending_count_;
    for (std::size_t i = 0; i < pending_count_; ++i) {
        last_commit_addresses_[i] = reinterpret_cast<std::uintptr_t>(pending_[i].target_word);
        last_commit_old_values_[i] = *pending_[i].target_word;
        last_commit_new_values_[i] = pending_[i].next_value;
        *pending_[i].target_word = pending_[i].next_value;
    }
    pending_count_ = 0;
    return HookCommit::Applied;
}

bool MockDeferredHookBackend::abort() noexcept {
    if (!transaction_open_) return true;
    pending_count_ = 0;
    transaction_open_ = false;
    return true;
}

std::uintptr_t MockDeferredHookBackend::last_commit_write_address(std::size_t i) const noexcept {
    return i < last_commit_write_count_ ? last_commit_addresses_[i] : 0;
}

HookEndpoint MockDeferredHookBackend::last_commit_old_value(std::size_t i) const noexcept {
    return i < last_commit_write_count_ ? last_commit_old_values_[i] : 0;
}

HookEndpoint MockDeferredHookBackend::last_commit_new_value(std::size_t i) const noexcept {
    return i < last_commit_write_count_ ? last_commit_new_values_[i] : 0;
}

} // namespace fc
