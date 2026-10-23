#pragma once

// Optional source-built Detours research backend. Include only in the
// authored-local-target test executable; never in Core or the default DLL.
#include "fc/hook_transactions.hpp"
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include "detours.h"

#include <array>
#include <cstddef>
#include <memory>
#include <vector>

namespace fc::research {

class DetoursCandidateHookBackend final : public HookBackend {
public:
    DetoursCandidateHookBackend() = default;
    ~DetoursCandidateHookBackend() noexcept override;
    DetoursCandidateHookBackend(const DetoursCandidateHookBackend&) = delete;
    DetoursCandidateHookBackend& operator=(const DetoursCandidateHookBackend&) = delete;

    HookSlot& reserve_slot(HookEndpoint target) override;
    void release_slot(HookSlot&) noexcept override;
    HookBegin begin() noexcept override;
    bool attach(HookSlot&, HookEndpoint replacement) noexcept override;
    bool detach(HookSlot&, HookEndpoint replacement) noexcept override;
    HookCommit commit() noexcept override;
    bool abort() noexcept override;

    std::size_t slot_count() const noexcept { return slots_.size(); }
    bool transaction_open() const noexcept { return transaction_open_; }
    // Historic diagnostic address of a backend-owned PVOID object. It may
    // become stale after release_slot; never dereference or use as a handle.
    std::uintptr_t last_detours_pointer_address() const noexcept { return last_pointer_address_; }

private:
    struct NativeSlot {
        explicit NativeSlot(HookEndpoint target) noexcept
            : generic(target), pointer(reinterpret_cast<void*>(target)) {}
        HookSlot generic;
        void* pointer; // Actual stable PVOID object passed as PVOID*.
        PDETOUR_TRAMPOLINE trampoline{}; // Actual stable optional output object.
        bool attached{};
    };
    struct Pending { NativeSlot* slot{}; bool attaching{}; };
    NativeSlot* find(HookSlot&) noexcept;
    HookBegin clean_failed_begin() noexcept;
    void clear_transaction() noexcept;

    std::vector<std::unique_ptr<NativeSlot>> slots_;
    std::array<Pending, HookTransactions::max_hooks> pending_{};
    std::size_t pending_count_{};
    std::uintptr_t last_pointer_address_{};
    DWORD owner_thread_{};
    bool transaction_open_{};
};

} // namespace fc::research
