// Only patches this executable's newly authored target function. It never
// loads, references, or patches an original game/core/wrapper module.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "detours.h"
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <thread>

namespace {
using Target = int (__cdecl*)(int);
__declspec(noinline) int __cdecl authored_target(int value) { return value * 3 + 5; }
void* target_slot = reinterpret_cast<void*>(&authored_target);
__declspec(noinline) int __cdecl authored_replacement(int value) {
    return reinterpret_cast<Target>(target_slot)(value) + 100;
}
unsigned checks{};
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
    ++checks;
}
int invoke(int value) {
    Target volatile call = &authored_target;
    return call(value);
}
void begin() {
    require(DetourTransactionBegin() == NO_ERROR, "begin on owner");
    require(DetourUpdateThread(GetCurrentThread()) == NO_ERROR, "update current thread");
}
void attach(PDETOUR_TRAMPOLINE& immediate) {
    require(DetourAttachEx(&target_slot, reinterpret_cast<void*>(&authored_replacement),
                          &immediate, nullptr, nullptr) == NO_ERROR,
            "attach owned local function");
}
}

int main() {
    try {
        const auto original = target_slot;
        require(invoke(4) == 17, "initial target behavior");
        PDETOUR_TRAMPOLINE immediate{};

        begin();
        attach(immediate);
        require(immediate && target_slot == original && invoke(4) == 17,
                "immediate trampoline output with target slot and code deferred");
        require(DetourTransactionAbort() == NO_ERROR && target_slot == original &&
                invoke(4) == 17, "abort leaves original code and slot");
        // The immediate trampoline is freed by abort and must not be used.
        immediate = nullptr;

        begin();
        attach(immediate);
        LONG other_commit{}, other_abort{};
        std::thread wrong_owner([&] {
            other_commit = DetourTransactionCommit();
            other_abort = DetourTransactionAbort();
        });
        wrong_owner.join();
        require(other_commit == ERROR_INVALID_OPERATION &&
                other_abort == ERROR_INVALID_OPERATION && target_slot == original,
                "wrong-thread calls reject without terminal cleanup");
        require(DetourTransactionBegin() == ERROR_INVALID_OPERATION,
                "wrong-thread rejection leaves original transaction active");
        require(DetourTransactionAbort() == NO_ERROR && target_slot == original,
                "same-thread abort closes pending transaction");
        immediate = nullptr;

        begin();
        attach(immediate);
        void* invalid_target = nullptr;
        require(DetourAttachEx(&invalid_target, reinterpret_cast<void*>(&authored_replacement),
                              nullptr, nullptr, nullptr) == ERROR_INVALID_HANDLE,
                "null target value creates pending error");
        void** failed_pointer{};
        require(DetourTransactionCommitEx(&failed_pointer) == ERROR_INVALID_HANDLE &&
                failed_pointer == &invalid_target && target_slot == original && invoke(4) == 17,
                "stored-error commit aborts earlier attach and reports failed slot");
        immediate = nullptr;

        begin();
        attach(immediate);
        require(target_slot == original, "successful attach still defers first slot");
        require(DetourTransactionCommit() == NO_ERROR &&
                target_slot == reinterpret_cast<void*>(immediate) && target_slot != original,
                "commit updates pointer-typed stable slot");
        require(invoke(4) == 117 && reinterpret_cast<Target>(target_slot)(4) == 17,
                "replacement and trampoline behavior");
        begin();
        require(DetourDetach(&target_slot, reinterpret_cast<void*>(&authored_replacement)) == NO_ERROR,
                "detach queued");
        require(target_slot == reinterpret_cast<void*>(immediate) && invoke(4) == 117,
                "detach waits for commit");
        require(DetourTransactionCommit() == NO_ERROR && target_slot == original && invoke(4) == 17,
                "detach commit restores original code and pointer");
        require(DetourTransactionCommit() == ERROR_INVALID_OPERATION &&
                DetourTransactionAbort() == ERROR_INVALID_OPERATION,
                "no remaining transaction");
        std::cout << "{\"passed\":true,\"checks\":" << checks
                  << ",\"scope\":\"Source-built upstream Detours with authored local target only\","
                     "\"original_native_executed\":false,\"native_game_adapter_admitted\":false}\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "authored Detours target probe failed: " << error.what() << '\n';
        return 1;
    }
}
