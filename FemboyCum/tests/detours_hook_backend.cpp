#include "detours_hook_backend.hpp"

#include <algorithm>
#include <exception>
#include <utility>

namespace fc::research {

DetoursCandidateHookBackend::~DetoursCandidateHookBackend() noexcept {
    // A pending Detours operation can retain &NativeSlot::pointer. The
    // service should already have terminated on active/uncertain teardown.
    if (transaction_open_ || !slots_.empty()) std::terminate();
}

DetoursCandidateHookBackend::NativeSlot*
DetoursCandidateHookBackend::find(HookSlot& slot) noexcept {
    for (const auto& item : slots_)
        if (&item->generic == &slot) return item.get();
    return nullptr;
}

HookSlot& DetoursCandidateHookBackend::reserve_slot(HookEndpoint target) {
    // Construct and append before publishing the reference. A vector
    // allocation failure destroys the local object and leaves no new slot.
    auto slot = std::make_unique<NativeSlot>(target);
    auto& result = slot->generic;
    slots_.push_back(std::move(slot));
    return result;
}

void DetoursCandidateHookBackend::release_slot(HookSlot& slot) noexcept {
    if (transaction_open_) std::terminate();
    const auto it = std::find_if(slots_.begin(), slots_.end(),
        [&slot](const auto& item) { return &item->generic == &slot; });
    if (it == slots_.end() || (*it)->attached) std::terminate();
    for (std::size_t i = 0; i < pending_count_; ++i)
        if (pending_[i].slot == it->get()) std::terminate();
    slots_.erase(it);
}

void DetoursCandidateHookBackend::clear_transaction() noexcept {
    pending_count_ = 0;
    owner_thread_ = 0;
    transaction_open_ = false;
}

HookBegin DetoursCandidateHookBackend::clean_failed_begin() noexcept {
    // Pinned source may acquire the owner before a later Begin helper fails.
    if (DetourTransactionAbort() == NO_ERROR) {
        clear_transaction();
        return HookBegin::Rejected;
    }
    return HookBegin::Uncertain;
}

HookBegin DetoursCandidateHookBackend::begin() noexcept {
    if (transaction_open_) return HookBegin::Uncertain;
    const auto result = DetourTransactionBegin();
    // A returned error code alone cannot tell whether Begin acquired its
    // owner before the region helper failed; that helper returns Win32
    // errors, which may collide with an early rejection code. Abort is the
    // only bounded positive terminal witness available here.
    owner_thread_ = GetCurrentThreadId();
    transaction_open_ = true;
    if (result != NO_ERROR) return clean_failed_begin();
    if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR)
        return clean_failed_begin();
    return HookBegin::Ready;
}

bool DetoursCandidateHookBackend::attach(HookSlot& slot,
                                         HookEndpoint replacement) noexcept {
    auto* native = find(slot);
    if (!transaction_open_ || owner_thread_ != GetCurrentThreadId() ||
        !native || native->attached || !replacement || pending_count_ == pending_.size())
        return false;
    for (std::size_t i = 0; i < pending_count_; ++i)
        if (pending_[i].slot == native) return false;
    last_pointer_address_ = reinterpret_cast<std::uintptr_t>(&native->pointer);
    const auto result = DetourAttachEx(&native->pointer,
        reinterpret_cast<void*>(replacement), &native->trampoline, nullptr, nullptr);
    if (result != NO_ERROR) return false;
    slot.trampoline_word = reinterpret_cast<HookEndpoint>(native->trampoline);
    pending_[pending_count_++] = Pending{native, true};
    return true;
}

bool DetoursCandidateHookBackend::detach(HookSlot& slot,
                                         HookEndpoint replacement) noexcept {
    auto* native = find(slot);
    if (!transaction_open_ || owner_thread_ != GetCurrentThreadId() ||
        !native || !native->attached || !replacement || pending_count_ == pending_.size())
        return false;
    for (std::size_t i = 0; i < pending_count_; ++i)
        if (pending_[i].slot == native) return false;
    last_pointer_address_ = reinterpret_cast<std::uintptr_t>(&native->pointer);
    if (DetourDetach(&native->pointer, reinterpret_cast<void*>(replacement)) != NO_ERROR)
        return false;
    pending_[pending_count_++] = Pending{native, false};
    return true;
}

HookCommit DetoursCandidateHookBackend::commit() noexcept {
    if (!transaction_open_ || owner_thread_ != GetCurrentThreadId())
        return HookCommit::Uncertain;
    const auto result = DetourTransactionCommit();
    if (result != NO_ERROR) {
        // A source Commit error may internally abort without checking its
        // result. Only our own terminal Abort return certifies cleanup.
        if (DetourTransactionAbort() != NO_ERROR) return HookCommit::Uncertain;
        clear_transaction();
        return HookCommit::Reverted;
    }
    for (std::size_t i = 0; i < pending_count_; ++i) {
        auto& item = pending_[i];
        item.slot->generic.target_word =
            reinterpret_cast<HookEndpoint>(item.slot->pointer);
        item.slot->attached = item.attaching;
    }
    clear_transaction();
    return HookCommit::Applied;
}

bool DetoursCandidateHookBackend::abort() noexcept {
    if (!transaction_open_ || owner_thread_ != GetCurrentThreadId()) return false;
    if (DetourTransactionAbort() != NO_ERROR) return false;
    clear_transaction();
    return true;
}

} // namespace fc::research
