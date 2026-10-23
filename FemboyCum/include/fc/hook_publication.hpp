#pragma once

#include "fc/hook_transactions.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <thread>

namespace fc::research {

// Research protocol for authored callers only. Every target invocation must
// hold a CallLease, including the full replacement/trampoline call. It does
// not intercept arbitrary callers of a patched native function.
class HookPublication final {
public:
    class CallLease final {
    public:
        CallLease(CallLease&& other) noexcept;
        CallLease& operator=(CallLease&& other) noexcept;
        ~CallLease() noexcept;
        CallLease(const CallLease&) = delete;
        CallLease& operator=(const CallLease&) = delete;

    private:
        friend class HookPublication;
        explicit CallLease(HookPublication& owner) noexcept : owner_(&owner) {}
        HookPublication* owner_{};
    };

    enum class InstallCode : std::uint8_t {
        Published, Rejected, WrongThread, InvalidState, Uncertain
    };
    struct InstallResult {
        InstallCode code;
        HookStatus hook_status;
    };
    enum class ShutdownCode : std::uint8_t {
        Clean, TimedOut, Retryable, WrongThread, Uncertain
    };
    struct ShutdownResult {
        ShutdownCode code;
        std::optional<HookStatus> hook_status;
        std::size_t in_flight;
    };

    explicit HookPublication(HookBackend& backend) noexcept;
    ~HookPublication() noexcept;
    HookPublication(const HookPublication&) = delete;
    HookPublication& operator=(const HookPublication&) = delete;

    // Only the constructing thread may manage the transaction. Install keeps
    // admission closed until its trampoline has been published and committed.
    InstallResult install(HookSpec spec);
    ShutdownResult shutdown(std::chrono::milliseconds timeout) noexcept;

    // Any authored caller may enter. A successful lease must cover its entire
    // target/replacement invocation; no direct entry is covered.
    std::optional<CallLease> try_enter() noexcept;
    HookEndpoint published_trampoline() const noexcept;
    std::size_t in_flight() const noexcept;

private:
    class PublishingBackend final : public HookBackend {
    public:
        PublishingBackend(HookBackend& inner, HookPublication& owner) noexcept
            : inner_(inner), owner_(owner) {}
        HookSlot& reserve_slot(HookEndpoint target) override;
        void release_slot(HookSlot& slot) noexcept override;
        HookBegin begin() noexcept override;
        bool attach(HookSlot& slot, HookEndpoint replacement) noexcept override;
        bool detach(HookSlot& slot, HookEndpoint replacement) noexcept override;
        HookCommit commit() noexcept override;
        bool abort() noexcept override;

    private:
        HookBackend& inner_;
        HookPublication& owner_;
    };

    enum class State : std::uint8_t { Dormant, Active, Quiescing, Stopped, Uncertain };
    static constexpr std::uint64_t closed_bit = std::uint64_t{1} << 63;
    static constexpr std::uint64_t count_mask = ~closed_bit;
    void leave() noexcept;
    void close() noexcept;
    bool wait_for_drain(std::chrono::milliseconds timeout) noexcept;
    void open() noexcept;
    void publish_trampoline(HookEndpoint value) noexcept;

    std::atomic<std::uint64_t> admissions_{closed_bit};
    mutable std::mutex publication_mutex_;
    HookEndpoint trampoline_{};
    std::mutex drain_mutex_;
    std::condition_variable drained_;
    PublishingBackend publishing_backend_;
    HookTransactions hooks_;
    const std::thread::id owner_;
    State state_{State::Dormant};
};

} // namespace fc::research
