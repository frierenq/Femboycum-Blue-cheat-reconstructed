#include "fc/hook_publication.hpp"

#include <exception>
#include <utility>

namespace fc::research {

HookSlot& HookPublication::PublishingBackend::reserve_slot(HookEndpoint target) {
    return inner_.reserve_slot(target);
}

void HookPublication::PublishingBackend::release_slot(HookSlot& slot) noexcept {
    inner_.release_slot(slot);
}

HookBegin HookPublication::PublishingBackend::begin() noexcept {
    return inner_.begin();
}

bool HookPublication::PublishingBackend::attach(HookSlot& slot,
                                                 HookEndpoint replacement) noexcept {
    if (!inner_.attach(slot, replacement)) return false;
    // The native backend copies DetourAttachEx's completed trampoline output
    // before returning. Publish before HookTransactions invokes commit().
    if (!slot.trampoline_word) return false;
    owner_.publish_trampoline(slot.trampoline_word);
    return true;
}

bool HookPublication::PublishingBackend::detach(HookSlot& slot,
                                                 HookEndpoint replacement) noexcept {
    return inner_.detach(slot, replacement);
}

HookCommit HookPublication::PublishingBackend::commit() noexcept {
    const auto result = inner_.commit();
    if (result == HookCommit::Reverted) owner_.publish_trampoline(0);
    return result;
}

bool HookPublication::PublishingBackend::abort() noexcept {
    if (!inner_.abort()) return false;
    owner_.publish_trampoline(0);
    return true;
}

HookPublication::CallLease::CallLease(CallLease&& other) noexcept
    : owner_(std::exchange(other.owner_, nullptr)) {}

HookPublication::CallLease&
HookPublication::CallLease::operator=(CallLease&& other) noexcept {
    if (this != &other) {
        if (owner_) owner_->leave();
        owner_ = std::exchange(other.owner_, nullptr);
    }
    return *this;
}

HookPublication::CallLease::~CallLease() noexcept {
    if (owner_) owner_->leave();
}

HookPublication::HookPublication(HookBackend& backend) noexcept
    : publishing_backend_(backend, *this), hooks_(publishing_backend_),
      owner_(std::this_thread::get_id()) {}

HookEndpoint HookPublication::published_trampoline() const noexcept {
    // A callback's lock occurs after the publisher unlocks before Commit,
    // giving a real publication handoff even without the admission gate.
    std::lock_guard lock(publication_mutex_);
    return trampoline_;
}

void HookPublication::publish_trampoline(HookEndpoint value) noexcept {
    std::lock_guard lock(publication_mutex_);
    trampoline_ = value;
}

HookPublication::~HookPublication() noexcept {
    // Neither an attached hook nor an uncertain transaction may outlive the
    // callback state in a continuing process. The service has the same rule.
    if (state_ != State::Dormant && state_ != State::Stopped) std::terminate();
    if (in_flight() != 0) std::terminate();
}

std::size_t HookPublication::in_flight() const noexcept {
    return static_cast<std::size_t>(admissions_.load(std::memory_order_acquire) & count_mask);
}

std::optional<HookPublication::CallLease> HookPublication::try_enter() noexcept {
    auto value = admissions_.load(std::memory_order_acquire);
    for (;;) {
        if ((value & closed_bit) || (value & count_mask) == count_mask)
            return std::nullopt;
        if (admissions_.compare_exchange_weak(value, value + 1,
                std::memory_order_acq_rel, std::memory_order_acquire))
            return CallLease(*this);
    }
}

void HookPublication::leave() noexcept {
    const auto before = admissions_.fetch_sub(1, std::memory_order_acq_rel);
    if ((before & count_mask) == 0) std::terminate();
    if ((before & count_mask) == 1 && (before & closed_bit)) {
        // Coordinate with wait_for_drain's mutex so its predicate/park step
        // cannot miss the final lease notification.
        std::lock_guard lock(drain_mutex_);
        drained_.notify_all();
    }
}

void HookPublication::close() noexcept {
    admissions_.fetch_or(closed_bit, std::memory_order_acq_rel);
}

bool HookPublication::wait_for_drain(std::chrono::milliseconds timeout) noexcept {
    std::unique_lock lock(drain_mutex_);
    return drained_.wait_for(lock, timeout, [this] { return in_flight() == 0; });
}

void HookPublication::open() noexcept {
    if (admissions_.load(std::memory_order_acquire) != closed_bit) std::terminate();
    admissions_.store(0, std::memory_order_release);
}

HookPublication::InstallResult HookPublication::install(HookSpec spec) {
    if (std::this_thread::get_id() != owner_)
        return {InstallCode::WrongThread, HookStatus::NoChange};
    if (state_ != State::Dormant)
        return {state_ == State::Uncertain ? InstallCode::Uncertain : InstallCode::InvalidState,
                HookStatus::NoChange};
    const auto result = hooks_.install({spec});
    if (result == HookStatus::Applied) {
        const auto snapshot = hooks_.snapshot(spec.role);
        if (!snapshot || !snapshot->trampoline_word ||
            published_trampoline() != snapshot->trampoline_word)
            std::terminate();
        state_ = State::Active;
        open();
        return {InstallCode::Published, result};
    }
    if (result == HookStatus::Uncertain || result == HookStatus::Poisoned) {
        state_ = State::Uncertain;
        return {InstallCode::Uncertain, result};
    }
    if (published_trampoline() != 0) std::terminate();
    return {InstallCode::Rejected, result};
}

HookPublication::ShutdownResult
HookPublication::shutdown(std::chrono::milliseconds timeout) noexcept {
    if (std::this_thread::get_id() != owner_)
        return {ShutdownCode::WrongThread, std::nullopt, in_flight()};
    if (state_ == State::Dormant || state_ == State::Stopped)
        return {ShutdownCode::Clean, std::nullopt, 0};
    if (state_ == State::Uncertain)
        return {ShutdownCode::Uncertain, HookStatus::Poisoned, in_flight()};
    close();
    state_ = State::Quiescing;
    if (!wait_for_drain(timeout))
        return {ShutdownCode::TimedOut, std::nullopt, in_flight()};

    // Every authorized target/replacement call has left. Detours may free
    // its trampoline in detach Commit; direct callers remain outside scope.
    publish_trampoline(0);
    const auto result = hooks_.detach_all();
    if (result == HookStatus::Applied) {
        state_ = State::Stopped;
        return {ShutdownCode::Clean, result, 0};
    }
    if (result == HookStatus::Uncertain || result == HookStatus::Poisoned) {
        state_ = State::Uncertain;
        return {ShutdownCode::Uncertain, result, 0};
    }
    if (result == HookStatus::NoChange) std::terminate();
    return {ShutdownCode::Retryable, result, 0};
}

} // namespace fc::research
