// Optional source-built Detours exercises only this executable's authored
// local function. Every concurrent target call takes the cooperative lease.
// No original module, game target, VM, or arbitrary-caller claim is involved.
#include "detours_hook_backend.hpp"
#include "fc/hook_publication.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <thread>

namespace {
using Target = int (__cdecl*)(int);
__declspec(noinline) int __cdecl authored_target(int value) { return value * 3 + 5; }
fc::research::HookPublication* publication{};
std::atomic<bool> hold_replacement{};
std::atomic<bool> replacement_entered{};
std::atomic<bool> release_replacement{};

__declspec(noinline) int __cdecl authored_replacement(int value) {
    if (hold_replacement.load(std::memory_order_acquire)) {
        replacement_entered.store(true, std::memory_order_release);
        while (!release_replacement.load(std::memory_order_acquire))
            std::this_thread::yield();
    }
    const auto call = reinterpret_cast<Target>(publication->published_trampoline());
    return call ? call(value) + 100 : -777;
}

int raw_invoke(int value) {
    Target volatile call = &authored_target;
    return call(value);
}

int invoke(int value) {
    auto lease = publication->try_enter();
    return lease ? raw_invoke(value) : -999;
}

class ObservingBackend final : public fc::HookBackend {
public:
    void observe(fc::research::HookPublication& value) noexcept { owner_ = &value; }
    fc::research::DetoursCandidateHookBackend& native() noexcept { return native_; }

    fc::HookSlot& reserve_slot(fc::HookEndpoint target) override {
        return native_.reserve_slot(target);
    }
    void release_slot(fc::HookSlot& slot) noexcept override { native_.release_slot(slot); }
    fc::HookBegin begin() noexcept override { return native_.begin(); }
    bool attach(fc::HookSlot& slot, fc::HookEndpoint replacement) noexcept override {
        const bool okay = native_.attach(slot, replacement);
        if (okay) attaching_ = true;
        return okay;
    }
    bool detach(fc::HookSlot& slot, fc::HookEndpoint replacement) noexcept override {
        const bool okay = native_.detach(slot, replacement);
        if (okay) detaching_ = true;
        return okay;
    }
    fc::HookCommit commit() noexcept override {
        if (attaching_) {
            const auto endpoint = owner_->published_trampoline();
            saw_precommit_publication_ = endpoint != 0 && !owner_->try_enter();
            if (endpoint) {
                const auto call = reinterpret_cast<Target>(endpoint);
                precommit_trampoline_result_ = call(4);
            }
            precommit_target_result_ = raw_invoke(4);
        }
        if (detaching_)
            saw_drained_detach_ = owner_->in_flight() == 0 &&
                owner_->published_trampoline() == 0 && !owner_->try_enter();
        const auto result = native_.commit();
        attaching_ = false;
        detaching_ = false;
        return result;
    }
    bool abort() noexcept override {
        const bool result = native_.abort();
        if (result) { attaching_ = false; detaching_ = false; }
        return result;
    }
    bool saw_precommit_publication() const noexcept { return saw_precommit_publication_; }
    int precommit_trampoline_result() const noexcept { return precommit_trampoline_result_; }
    int precommit_target_result() const noexcept { return precommit_target_result_; }
    bool saw_drained_detach() const noexcept { return saw_drained_detach_; }

private:
    fc::research::DetoursCandidateHookBackend native_;
    fc::research::HookPublication* owner_{};
    bool attaching_{};
    bool detaching_{};
    bool saw_precommit_publication_{};
    bool saw_drained_detach_{};
    int precommit_trampoline_result_{};
    int precommit_target_result_{};
};

unsigned checks{};
void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
    ++checks;
}

bool await_entered() {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!replacement_entered.load(std::memory_order_acquire)) {
        if (std::chrono::steady_clock::now() >= deadline) return false;
        std::this_thread::yield();
    }
    return true;
}
} // namespace

int main() {
    try {
        ObservingBackend backend;
        fc::research::HookPublication session(backend);
        publication = &session;
        backend.observe(session);
        require(raw_invoke(4) == 17 && invoke(4) == -999,
                "authored target unpatched while admission closed");
        const auto installed = session.install({fc::HookRole::Feedback,
            reinterpret_cast<fc::HookEndpoint>(&authored_target),
            reinterpret_cast<fc::HookEndpoint>(&authored_replacement)});
        if (installed.code != fc::research::HookPublication::InstallCode::Published)
            throw std::runtime_error("authored Detours publication install failed");
        std::thread worker;
        try {
            require(backend.saw_precommit_publication() &&
                    backend.precommit_trampoline_result() == 17 &&
                    backend.precommit_target_result() == 17,
                    "source-built trampoline is published and callable before commit");
            require(backend.native().slot_count() == 1 &&
                    session.published_trampoline() != 0 && invoke(4) == 117,
                    "authored target redirects through published trampoline");

            hold_replacement.store(true, std::memory_order_release);
            std::atomic<int> worker_result{};
            worker = std::thread([&] { worker_result.store(invoke(4)); });
            require(await_entered(), "replacement holds an upstream target lease");
            const auto timed = session.shutdown(std::chrono::milliseconds(0));
            require(timed.code == fc::research::HookPublication::ShutdownCode::TimedOut &&
                    timed.in_flight == 1 && backend.native().slot_count() == 1 &&
                    session.published_trampoline() != 0,
                    "shutdown timeout retains trampoline and native slot");
            require(invoke(4) == -999, "closed admission denies a new target call");
            release_replacement.store(true, std::memory_order_release);
            worker.join();
            require(worker_result.load() == 117 && session.in_flight() == 0,
                    "blocked replacement resumes through still-valid trampoline");

            const auto clean = session.shutdown(std::chrono::milliseconds(100));
            require(clean.code == fc::research::HookPublication::ShutdownCode::Clean &&
                    clean.hook_status == fc::HookStatus::Applied &&
                    backend.native().slot_count() == 0 &&
                    !backend.native().transaction_open(),
                    "drained authored calls allow terminal detach and slot release");
            require(backend.saw_drained_detach() &&
                    session.published_trampoline() == 0 && !session.try_enter(),
                    "detach commit sees closed gate, zero leases and no publication");
            require(raw_invoke(4) == 17, "authored target restored after detach");
        } catch (...) {
            release_replacement.store(true, std::memory_order_release);
            if (worker.joinable()) worker.join();
            for (unsigned i = 0; i < 4 && backend.native().slot_count(); ++i)
                (void)session.shutdown(std::chrono::milliseconds(100));
            throw;
        }
        publication = nullptr;
        std::cout << "{\"passed\":true,\"checks\":" << checks
                  << ",\"scope\":\"source-built Detours, authored local target, cooperative callers\","
                     "\"original_native_executed\":false,\"native_game_adapter_admitted\":false}\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "authored Detours publication test failed: " << error.what() << '\n';
        return 1;
    }
}
