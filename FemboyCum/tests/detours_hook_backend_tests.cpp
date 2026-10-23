// The only native target in this test is this executable's authored function.
// No original module, game function, VM, or engine address is referenced.
#include "detours_hook_backend.hpp"

#include <cstdint>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <thread>

namespace {
using Target = int (__cdecl*)(int);
__declspec(noinline) int __cdecl authored_target(int value) { return value * 3 + 5; }
Target trampoline{};
__declspec(noinline) int __cdecl authored_replacement(int value) {
    return trampoline ? trampoline(value) + 100 : -777;
}
int invoke(int value) {
    Target volatile call = &authored_target;
    return call(value);
}
unsigned checks{};
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
    ++checks;
}
struct CleanupOnFailure {
    fc::HookTransactions& hooks;
    ~CleanupOnFailure() noexcept {
        for (unsigned attempt = 0; attempt < 4 && hooks.size() && !hooks.poisoned(); ++attempt)
            (void)hooks.detach_all();
    }
};
struct DirectCleanup {
    fc::research::DetoursCandidateHookBackend& backend;
    fc::HookSlot* slot;
    ~DirectCleanup() noexcept {
        if (!slot) return;
        if (backend.transaction_open() && !backend.abort()) std::terminate();
        backend.release_slot(*slot);
    }
};
}

int main() {
    try {
        using fc::HookBegin;
        using fc::HookCommit;
        using fc::HookEndpoint;
        using fc::HookRole;
        using fc::HookStatus;
        fc::research::DetoursCandidateHookBackend backend;
        const auto target = reinterpret_cast<HookEndpoint>(&authored_target);
        const auto replacement = reinterpret_cast<HookEndpoint>(&authored_replacement);
        require(invoke(4) == 17, "authored target before hook");

        // Exercise the native backend directly to inspect the first-slot
        // timing before a service-level commit makes the slot active.
        auto& direct = backend.reserve_slot(target);
        DirectCleanup direct_cleanup{backend, &direct};
        require(backend.begin() == HookBegin::Ready && backend.transaction_open(),
                "native backend opens authored transaction");
        require(backend.attach(direct, replacement), "native attach queues");
        require(backend.last_detours_pointer_address() != 0 &&
                direct.target_word == target &&
                direct.trampoline_word != 0 && invoke(4) == 17,
                "immediate trampoline, deferred target word and code");
        require(backend.abort() && !backend.transaction_open() &&
                direct.target_word == target && invoke(4) == 17,
                "native abort is terminal without target redirection");
        require(backend.begin() == HookBegin::Ready &&
                backend.attach(direct, replacement),
                "second authored transaction queues before wrong-thread commit");
        HookCommit foreign_commit = HookCommit::Applied;
        std::thread wrong_owner([&] { foreign_commit = backend.commit(); });
        wrong_owner.join();
        require(foreign_commit == HookCommit::Uncertain &&
                backend.transaction_open() && direct.target_word == target,
                "wrong-thread backend commit retains owner transaction and slot");
        require(backend.abort() && !backend.transaction_open() &&
                direct.target_word == target && invoke(4) == 17,
                "owner abort terminates after rejected foreign commit");
        backend.release_slot(direct);
        direct_cleanup.slot = nullptr;
        require(backend.slot_count() == 0, "aborted slot released");

        fc::HookTransactions hooks(backend);
        CleanupOnFailure cleanup{hooks};
        require(hooks.install({{HookRole::Feedback, target, replacement}}) ==
                    HookStatus::Applied,
                "service commits authored local hook");
        const auto installed = hooks.snapshot(HookRole::Feedback);
        require(installed && installed->original == target &&
                installed->trampoline_word != 0 &&
                installed->target_word == installed->trampoline_word &&
                backend.last_detours_pointer_address() != 0 &&
                backend.last_detours_pointer_address() !=
                    installed->target_word_storage_address,
                "service retains typed native slot through committed trampoline");
        const auto stable_native_address = backend.last_detours_pointer_address();
        trampoline = reinterpret_cast<Target>(installed->trampoline_word);
        require(invoke(4) == 117 && trampoline(4) == 17,
                "authored target redirects and trampoline reaches original");
        require(hooks.detach_all() == HookStatus::Applied &&
                hooks.size() == 0 && backend.slot_count() == 0 &&
                !backend.transaction_open() &&
                backend.last_detours_pointer_address() == stable_native_address,
                "service commits detach then retires native slot");
        trampoline = nullptr;
        require(invoke(4) == 17, "authored target restored");
        std::cout << "{\"passed\":true,\"checks\":" << checks
                  << ",\"scope\":\"authored local target and pinned source Detours only\","
                     "\"original_native_executed\":false,\"native_game_adapter_admitted\":false}\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "authored hook backend test failed: " << error.what() << '\n';
        return 1;
    }
}
