#include "fc/hook_transactions.hpp"

#include <array>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <iostream>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#if defined(_WIN32)
#include <process.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {
unsigned checks{};
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
    ++checks;
}
struct CleanupOnFailure {
    fc::HookTransactions& hooks;
    fc::MockDeferredHookBackend& backend;
    ~CleanupOnFailure() noexcept {
        // Preserve the assertion diagnostic on ordinary terminal failures.
        // One-shot mock rejections may require a retry during unwinding.
        backend.reject_detach_call(0);
        for (unsigned attempt = 0; attempt < 4 && hooks.size() && !hooks.poisoned(); ++attempt)
            (void)hooks.detach_all();
    }
};

class FaultBackend final : public fc::HookBackend {
public:
    fc::MockDeferredHookBackend mock;
    std::array<fc::HookSlot*, fc::HookTransactions::max_hooks> returned{};
    std::size_t reserve_calls{};
    std::size_t throw_reserve_at{};
    bool fail_next_abort{};
    bool uncertain_next_commit{};
    bool uncertain_next_begin{};

    fc::HookSlot& reserve_slot(fc::HookEndpoint target) override {
        ++reserve_calls;
        if (reserve_calls == throw_reserve_at) throw std::bad_alloc();
        auto& slot = mock.reserve_slot(target);
        returned[reserve_calls - 1] = &slot;
        return slot;
    }
    void release_slot(fc::HookSlot& slot) noexcept override { mock.release_slot(slot); }
    fc::HookBegin begin() noexcept override {
        if (uncertain_next_begin) {
            uncertain_next_begin = false;
            (void)mock.begin(); // Model an owner acquired before Begin reported failure.
            return fc::HookBegin::Uncertain;
        }
        return mock.begin();
    }
    bool attach(fc::HookSlot& slot, fc::HookEndpoint replacement) noexcept override {
        return mock.attach(slot, replacement);
    }
    bool detach(fc::HookSlot& slot, fc::HookEndpoint replacement) noexcept override {
        return mock.detach(slot, replacement);
    }
    fc::HookCommit commit() noexcept override {
        if (uncertain_next_commit) {
            uncertain_next_commit = false;
            return fc::HookCommit::Uncertain; // Keep the queued write live.
        }
        return mock.commit();
    }
    bool abort() noexcept override {
        if (fail_next_abort) {
            fail_next_abort = false;
            return false; // Keep the queued write live.
        }
        return mock.abort();
    }
};

bool terminate_expected{};
void child_terminate() noexcept { std::_Exit(terminate_expected ? 77 : 81); }
void child_require(bool condition, const char* message) noexcept {
    if (condition) return;
    std::cerr << "child ownership failure: " << message << '\n' << std::flush;
    std::_Exit(79);
}

int run_poison_child(std::string_view mode) {
    std::set_terminate(child_terminate);
    const fc::HookSpec feedback{fc::HookRole::Feedback, 101, 301};
    const fc::HookSpec reset{fc::HookRole::ResetCallback, 202, 402};
    FaultBackend backend;
    {
        fc::HookTransactions hooks(backend);
        if (mode == "--uncertain-begin") {
            backend.uncertain_next_begin = true;
            child_require(hooks.install({feedback}) == fc::HookStatus::Uncertain,
                          "uncertain begin reported");
            child_require(hooks.poisoned() && backend.mock.slot_count() == 1 &&
                          backend.mock.pending_count() == 0 && backend.mock.transaction_open() &&
                          backend.returned[0] &&
                          backend.returned[0]->target_word == feedback.target,
                          "uncertain begin retains reserved slot and owner state");
        } else if (mode == "--uncertain-commit") {
            backend.uncertain_next_commit = true;
            child_require(hooks.install({feedback}) == fc::HookStatus::Uncertain,
                          "uncertain attach commit reported");
            auto* slot = backend.returned[0];
            child_require(hooks.poisoned() && slot && backend.mock.slot_count() == 1 &&
                          backend.mock.pending_count() == 1 && backend.mock.transaction_open() &&
                          slot->target_word == feedback.target && slot->trampoline_word != 0,
                          "uncertain commit retains slot and deferred write");
            const auto expected = slot->trampoline_word;
            child_require(backend.mock.commit() == fc::HookCommit::Applied &&
                          backend.mock.last_commit_write_address(0) ==
                              reinterpret_cast<std::uintptr_t>(&slot->target_word) &&
                          slot->target_word == expected,
                          "late commit writes through retained attach slot");
        } else if (mode == "--failed-abort") {
            backend.mock.reject_attach_call(2);
            backend.fail_next_abort = true;
            child_require(hooks.install({feedback, reset}) == fc::HookStatus::Uncertain,
                          "failed abort reports uncertainty");
            auto* first = backend.returned[0];
            auto* second = backend.returned[1];
            child_require(hooks.poisoned() && first && second &&
                          backend.mock.slot_count() == 2 && backend.mock.pending_count() == 1 &&
                          backend.mock.transaction_open() && first->target_word == feedback.target,
                          "failed abort retains both slots and first queued write");
            const auto expected = first->trampoline_word;
            child_require(backend.mock.commit() == fc::HookCommit::Applied &&
                          backend.mock.last_commit_write_address(0) ==
                              reinterpret_cast<std::uintptr_t>(&first->target_word) &&
                          first->target_word == expected && second->target_word == reset.target,
                          "late commit after failed abort uses retained slot");
        } else if (mode == "--uncertain-detach-begin") {
            child_require(hooks.install({feedback}) == fc::HookStatus::Applied,
                          "setup attach applied");
            auto* slot = backend.returned[0];
            const auto attached_word = slot->target_word;
            backend.uncertain_next_begin = true;
            child_require(hooks.detach_all() == fc::HookStatus::Uncertain,
                          "uncertain detach begin reported");
            child_require(hooks.poisoned() && hooks.size() == 1 &&
                          backend.mock.slot_count() == 1 && backend.mock.transaction_open() &&
                          backend.mock.pending_count() == 0 &&
                          slot->target_word == attached_word,
                          "uncertain detach begin retains active slot");
        } else if (mode == "--uncertain-detach") {
            child_require(hooks.install({feedback}) == fc::HookStatus::Applied,
                          "setup attach applied");
            auto* slot = backend.returned[0];
            const auto attached_word = slot->target_word;
            backend.uncertain_next_commit = true;
            child_require(hooks.detach_all() == fc::HookStatus::Uncertain,
                          "uncertain detach commit reported");
            child_require(hooks.poisoned() && hooks.size() == 1 && slot &&
                          backend.mock.slot_count() == 1 && backend.mock.pending_count() == 1 &&
                          backend.mock.transaction_open() && slot->target_word == attached_word,
                          "uncertain detach retains active slot and deferred restore");
            child_require(backend.mock.commit() == fc::HookCommit::Applied &&
                          backend.mock.last_commit_write_address(0) ==
                              reinterpret_cast<std::uintptr_t>(&slot->target_word) &&
                          slot->target_word == feedback.target,
                          "late detach commit restores through retained slot");
        } else {
            child_require(false, "unknown child mode");
        }
        child_require(hooks.install({feedback}) == fc::HookStatus::Poisoned,
                      "poisoned service rejects further installation");
        terminate_expected = true;
    }
    return 78; // The poisoned destructor must not return.
}

int run_child(const std::string& executable, const char* mode) {
#if defined(_WIN32)
    const char* args[] = {executable.c_str(), mode, nullptr};
    return static_cast<int>(_spawnv(_P_WAIT, executable.c_str(), args));
#else
    const auto pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        char* const args[] = {const_cast<char*>(executable.c_str()), const_cast<char*>(mode), nullptr};
        execv(executable.c_str(), args);
        std::_Exit(80);
    }
    int status{};
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
#endif
}
}

int main(int argc, char** argv) {
    if (argc == 2) return run_poison_child(argv[1]);
    try {
        using fc::HookRole;
        using fc::HookSpec;
        using fc::HookStatus;
        {
            fc::MockDeferredHookBackend direct;
            auto& slot = direct.reserve_slot(707);
            auto* stable_target_word = &slot.target_word;
            require(direct.begin() == fc::HookBegin::Ready && direct.attach(slot, 909),
                    "direct mock attach queued");
            const auto first_trampoline = slot.trampoline_word;
            require(first_trampoline != 0 && slot.target_word == 707 &&
                    direct.pending_count() == 1,
                    "attach publishes trampoline but defers target-word write");
            require(direct.abort() && slot.target_word == 707 &&
                    direct.pending_count() == 0,
                    "abort clears queued write without changing target word");
            require(direct.begin() == fc::HookBegin::Ready && direct.attach(slot, 909) &&
                    slot.target_word == 707 && &slot.target_word == stable_target_word,
                    "second attach still defers write through the same slot");
            const auto committed_trampoline = slot.trampoline_word;
            require(direct.commit() == fc::HookCommit::Applied &&
                    slot.target_word == committed_trampoline &&
                    direct.last_commit_write_address(0) ==
                        reinterpret_cast<std::uintptr_t>(stable_target_word),
                    "commit writes through the stable slot after attach returns");
            require(direct.begin() == fc::HookBegin::Ready && direct.detach(slot, 909) &&
                    slot.target_word == committed_trampoline,
                    "detach also defers target-word restoration");
            require(direct.commit() == fc::HookCommit::Applied && slot.target_word == 707,
                    "detach commit restores original target word");
            direct.release_slot(slot);
            require(direct.slot_count() == 0, "direct mock slot released after terminal detach");
        }
        fc::MockDeferredHookBackend backend;
        fc::HookTransactions hooks(backend);
        CleanupOnFailure cleanup{hooks, backend};
        const HookSpec feedback{HookRole::Feedback, 101, 301};
        const HookSpec reset{HookRole::ResetCallback, 202, 402};

        require(hooks.install({}) == HookStatus::NoChange, "empty batch no change");
        require(hooks.install({{HookRole::Feedback, 0, 301}}) == HookStatus::InvalidSpec,
                "zero target rejected");
        require(hooks.install({{HookRole::Feedback, 101, 0}}) == HookStatus::InvalidSpec,
                "zero replacement rejected");
        require(hooks.install({feedback, feedback}) == HookStatus::DuplicateRole,
                "duplicate role rejected before backend allocation");
        require(backend.slot_count() == 0 && !backend.transaction_open(),
                "validation leaves backend untouched");

        {
            FaultBackend allocation_failure;
            allocation_failure.throw_reserve_at = 2;
            fc::HookTransactions staged(allocation_failure);
            bool caught = false;
            try { (void)staged.install({feedback, reset}); }
            catch (const std::bad_alloc&) { caught = true; }
            require(caught && staged.size() == 0 && !staged.poisoned() &&
                    allocation_failure.mock.slot_count() == 0 &&
                    allocation_failure.mock.pending_count() == 0 &&
                    !allocation_failure.mock.transaction_open(),
                    "second reserve throw releases first returned slot before begin");
        }

        backend.reject_next_begin();
        require(hooks.install({feedback}) == HookStatus::BeginRejected,
                "begin rejection reported");
        require(backend.slot_count() == 0, "begin rejection releases reserved slot");

        backend.reject_attach_call(2);
        require(hooks.install({feedback, reset}) == HookStatus::OperationRejected,
                "second attach rejection aborts first pending attach");
        require(backend.slot_count() == 0 && backend.pending_count() == 0 &&
                !backend.transaction_open(), "abort precedes release of every staged slot");

        backend.revert_next_commit();
        require(hooks.install({feedback}) == HookStatus::CommitReverted,
                "terminal commit rollback reported");
        require(backend.slot_count() == 0 && backend.pending_count() == 0,
                "terminal rollback releases staged slot");

        require(hooks.install({feedback}) == HookStatus::Applied, "first role installed");
        const auto first = hooks.snapshot(HookRole::Feedback);
        require(first.has_value(), "installed role visible");
        require(first->original == feedback.target && first->trampoline_word != 0 &&
                first->target_word == first->trampoline_word, "mock committed trampoline");
        require(backend.last_commit_write_count() == 1 &&
                backend.last_commit_old_value(0) == feedback.target &&
                backend.last_commit_new_value(0) == first->trampoline_word,
                "target word changed only at commit, after immediate trampoline output");
        require(backend.last_commit_write_address(0) == first->target_word_storage_address,
                "deferred write used backend-owned stable slot");
        require(hooks.install({feedback}) == HookStatus::DuplicateRole,
                "existing role cannot be installed twice");

        require(hooks.install({reset}) == HookStatus::Applied, "second role installed");
        const auto after_growth = hooks.snapshot(HookRole::Feedback);
        require(after_growth && after_growth->target_word_storage_address ==
                first->target_word_storage_address,
                "record-vector growth cannot move backend-owned target word");
        require(hooks.size() == 2 && backend.slot_count() == 2,
                "two typed roles hold two slots");

        backend.reject_next_begin();
        require(hooks.detach_all() == HookStatus::BeginRejected &&
                hooks.size() == 2 && backend.slot_count() == 2,
                "terminal detach begin rejection keeps installed slots");

        backend.reject_detach_call(1);
        require(hooks.detach_all() == HookStatus::OperationRejected,
                "detach rejection aborts without releasing active slots");
        require(hooks.size() == 2 && backend.slot_count() == 2 &&
                backend.pending_count() == 0, "failed detach retains installed roles");

        backend.revert_next_commit();
        require(hooks.detach_all() == HookStatus::CommitReverted,
                "detach commit rollback retains active roles");
        require(hooks.size() == 2 && backend.slot_count() == 2,
                "reverted detach retains stable slots");

        require(hooks.detach_all() == HookStatus::Applied, "explicit detach succeeds");
        require(hooks.size() == 0 && backend.slot_count() == 0 &&
                backend.pending_count() == 0, "slots released only after detach commit");
        require(backend.last_commit_write_count() == 2 &&
                backend.last_commit_old_value(0) != backend.last_commit_new_value(0) &&
                backend.last_commit_old_value(1) != backend.last_commit_new_value(1),
                "detach also defers target-word restoration to commit");
        require(hooks.detach_all() == HookStatus::NoChange, "repeat detach idempotent");
        require(!hooks.poisoned(), "all tested terminal paths remain usable");
        const auto executable = std::filesystem::absolute(argv[0]).string();
        for (const auto* mode : {"--uncertain-begin", "--uncertain-commit",
                                 "--failed-abort", "--uncertain-detach-begin",
                                 "--uncertain-detach"}) {
            const int exit_code = run_child(executable, mode);
            if (exit_code != 77)
                throw std::runtime_error(std::string("poison child ") + mode +
                                         " exited " + std::to_string(exit_code) + " instead of 77");
            ++checks;
        }
        std::cout << "hook transaction checks: " << checks << '\n';
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "hook transaction test failure: " << e.what() << '\n';
        return 1;
    }
}
