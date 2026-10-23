// Authored pointer-swap target only. No original module, game target, VM or
// source-built Detours operation is executed in this protocol test.
#include "fc/hook_publication.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <thread>

namespace {
using Target = int (*)(int);
int authored_target(int value) { return value * 3 + 5; }
std::atomic<Target> current{&authored_target};
fc::research::HookPublication* publication{};
std::atomic<bool> hold_replacement{};
std::atomic<bool> replacement_entered{};
std::atomic<bool> release_replacement{};

int authored_replacement(int value) {
    if (hold_replacement.load(std::memory_order_acquire)) {
        replacement_entered.store(true, std::memory_order_release);
        while (!release_replacement.load(std::memory_order_acquire))
            std::this_thread::yield();
    }
    const auto endpoint = publication->published_trampoline();
    const auto call = reinterpret_cast<Target>(endpoint);
    return call ? call(value) + 100 : -777;
}

int invoke(int value) {
    auto lease = publication->try_enter();
    if (!lease) return -999;
    return current.load(std::memory_order_acquire)(value);
}

class AuthoredSwapBackend final : public fc::HookBackend {
public:
    explicit AuthoredSwapBackend(std::atomic<Target>& target) noexcept : target_(target) {}
    void observe(fc::research::HookPublication& value) noexcept { observer_ = &value; }
    fc::HookSlot& reserve_slot(fc::HookEndpoint target) override {
        if (slot_) throw std::logic_error("single authored slot only");
        auto value = std::make_unique<fc::HookSlot>(target);
        auto& reference = *value;
        slot_ = std::move(value);
        return reference;
    }
    void release_slot(fc::HookSlot& slot) noexcept override {
        if (transaction_ || attached_ || slot_.get() != &slot) std::terminate();
        slot_.reset();
    }
    fc::HookBegin begin() noexcept override {
        if (transaction_) return fc::HookBegin::Uncertain;
        transaction_ = true;
        pending_ = Pending::None;
        return fc::HookBegin::Ready;
    }
    bool attach(fc::HookSlot& slot, fc::HookEndpoint replacement) noexcept override {
        if (!transaction_ || pending_ != Pending::None || slot_.get() != &slot || attached_)
            return false;
        replacement_ = reinterpret_cast<Target>(replacement);
        slot.trampoline_word = slot.original;
        pending_ = Pending::Attach;
        return true;
    }
    bool detach(fc::HookSlot& slot, fc::HookEndpoint replacement) noexcept override {
        if (!transaction_ || pending_ != Pending::None || slot_.get() != &slot ||
            !attached_ || replacement_ != reinterpret_cast<Target>(replacement))
            return false;
        pending_ = Pending::Detach;
        return true;
    }
    fc::HookCommit commit() noexcept override {
        if (!transaction_) return fc::HookCommit::Uncertain;
        if (pending_ == Pending::Attach) {
            saw_precommit_publication_ = observer_ &&
                observer_->published_trampoline() == slot_->original;
            saw_closed_install_gate_ = observer_ && !observer_->try_enter();
        }
        if (pending_ == Pending::Detach) {
            saw_drained_detach_ = observer_ && observer_->in_flight() == 0 &&
                observer_->published_trampoline() == 0 && !observer_->try_enter();
        }
        transaction_ = false;
        if (revert_next_detach_ && pending_ == Pending::Detach) {
            revert_next_detach_ = false;
            pending_ = Pending::None;
            return fc::HookCommit::Reverted;
        }
        if (pending_ == Pending::Attach) {
            target_.store(replacement_, std::memory_order_release);
            slot_->target_word = slot_->trampoline_word;
            attached_ = true;
        } else if (pending_ == Pending::Detach) {
            target_.store(reinterpret_cast<Target>(slot_->original),
                          std::memory_order_release);
            slot_->target_word = slot_->original;
            attached_ = false;
            ++detach_commits_;
        }
        pending_ = Pending::None;
        return fc::HookCommit::Applied;
    }
    bool abort() noexcept override {
        if (!transaction_) return false;
        transaction_ = false;
        pending_ = Pending::None;
        return true;
    }
    void revert_next_detach() noexcept { revert_next_detach_ = true; }
    bool saw_precommit_publication() const noexcept { return saw_precommit_publication_; }
    bool saw_closed_install_gate() const noexcept { return saw_closed_install_gate_; }
    bool saw_drained_detach() const noexcept { return saw_drained_detach_; }
    unsigned detach_commits() const noexcept { return detach_commits_; }
    bool attached() const noexcept { return attached_; }
    bool has_slot() const noexcept { return static_cast<bool>(slot_); }

private:
    enum class Pending { None, Attach, Detach };
    std::atomic<Target>& target_;
    fc::research::HookPublication* observer_{};
    std::unique_ptr<fc::HookSlot> slot_;
    Target replacement_{};
    Pending pending_{Pending::None};
    unsigned detach_commits_{};
    bool transaction_{};
    bool attached_{};
    bool revert_next_detach_{};
    bool saw_precommit_publication_{};
    bool saw_closed_install_gate_{};
    bool saw_drained_detach_{};
};

unsigned checks{};
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
    ++checks;
}

bool await_entered() {
    const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!replacement_entered.load(std::memory_order_acquire)) {
        if (std::chrono::steady_clock::now() >= until) return false;
        std::this_thread::yield();
    }
    return true;
}
} // namespace

int main() {
    try {
        AuthoredSwapBackend backend(current);
        fc::research::HookPublication session(backend);
        publication = &session;
        backend.observe(session);
        require(!session.try_enter(), "admission starts closed");
        const auto installed = session.install({fc::HookRole::Feedback,
            reinterpret_cast<fc::HookEndpoint>(&authored_target),
            reinterpret_cast<fc::HookEndpoint>(&authored_replacement)});
        if (installed.code != fc::research::HookPublication::InstallCode::Published)
            throw std::runtime_error("authored publication install failed");
        std::thread worker;
        try {
            require(backend.saw_precommit_publication(),
                    "trampoline published before target redirect commit");
            require(backend.saw_closed_install_gate(),
                    "authored target admission remains closed during commit");
            require(invoke(4) == 117, "replacement calls published authored target");
            fc::research::HookPublication::ShutdownResult foreign{};
            std::thread other([&] { foreign = session.shutdown(std::chrono::milliseconds(0)); });
            other.join();
            require(foreign.code ==
                    fc::research::HookPublication::ShutdownCode::WrongThread &&
                    invoke(4) == 117, "wrong-thread shutdown preserves admission");

            hold_replacement.store(true, std::memory_order_release);
            std::atomic<int> worker_result{};
            worker = std::thread([&] { worker_result.store(invoke(4)); });
            require(await_entered(), "authored replacement entered while lease held");
            const auto timed = session.shutdown(std::chrono::milliseconds(0));
            require(timed.code == fc::research::HookPublication::ShutdownCode::TimedOut &&
                    timed.in_flight == 1 && backend.detach_commits() == 0,
                    "timeout keeps trampoline and attached hook while call runs");
            require(session.published_trampoline() != 0 && invoke(4) == -999,
                    "closed gate denies new callers without clearing live trampoline");
            release_replacement.store(true, std::memory_order_release);
            worker.join();
            require(worker_result.load() == 117 && session.in_flight() == 0,
                    "lease leaves after complete replacement and call-through");

            backend.revert_next_detach();
            const auto retry = session.shutdown(std::chrono::milliseconds(100));
            require(retry.code == fc::research::HookPublication::ShutdownCode::Retryable &&
                    retry.hook_status == fc::HookStatus::CommitReverted &&
                    backend.attached() && backend.has_slot() && invoke(4) == -999,
                    "terminal detach rollback retains slot behind closed gate");
            const auto clean = session.shutdown(std::chrono::milliseconds(100));
            require(clean.code == fc::research::HookPublication::ShutdownCode::Clean &&
                    clean.hook_status == fc::HookStatus::Applied &&
                    backend.detach_commits() == 1 && !backend.has_slot(),
                    "retry commits detach and releases authored slot");
            require(backend.saw_drained_detach() &&
                    session.published_trampoline() == 0 && !session.try_enter(),
                    "detach sees drained calls and no published trampoline");
            require(current.load() == &authored_target,
                    "authored pointer swap restored after shutdown");
        } catch (...) {
            release_replacement.store(true, std::memory_order_release);
            if (worker.joinable()) worker.join();
            for (unsigned i = 0; i < 4 && backend.attached(); ++i)
                (void)session.shutdown(std::chrono::milliseconds(100));
            throw;
        }
        publication = nullptr;
        std::cout << "authored hook publication checks: " << checks << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "authored publication test failed: " << error.what() << '\n';
        return 1;
    }
}
