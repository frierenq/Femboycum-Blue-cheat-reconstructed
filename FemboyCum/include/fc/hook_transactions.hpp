#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace fc {

// Experimental roles proved by static descriptors. No native address is a key.
enum class HookRole : std::uint8_t { Feedback, ResetCallback };
using HookEndpoint = std::uintptr_t;

struct HookSpec {
    HookRole role{};
    HookEndpoint target{};
    HookEndpoint replacement{};
};

// Allocated by a backend. Neither the slot nor its target word may move while
// a transaction can retain &target_word for a deferred commit/abort/detach.
struct HookSlot {
    explicit HookSlot(HookEndpoint initial) noexcept : original(initial), target_word(initial) {}
    HookSlot(const HookSlot&) = delete;
    HookSlot& operator=(const HookSlot&) = delete;
    const HookEndpoint original;
    HookEndpoint target_word;
    HookEndpoint trampoline_word{};
};

enum class HookCommit : std::uint8_t { Applied, Reverted, Uncertain };
enum class HookBegin : std::uint8_t { Ready, Rejected, Uncertain };

class HookBackend {
public:
    virtual ~HookBackend() = default;
    // Backend owns the heap slot; reserve may throw before begin. A throw
    // must leave no newly backend-owned slot or other pending side effect:
    // the caller can release only a slot whose reference was returned.
    virtual HookSlot& reserve_slot(HookEndpoint target) = 0;
    // Only after a terminal transaction and no installed hook uses this slot.
    virtual void release_slot(HookSlot&) noexcept = 0;
    // Rejected guarantees no transaction owned by this backend remains;
    // Uncertain requires slot retention even if no operation was queued.
    virtual HookBegin begin() noexcept = 0;
    // attach/detach may have queued earlier operations before a later
    // operation returns false.
    virtual bool attach(HookSlot&, HookEndpoint replacement) noexcept = 0;
    virtual bool detach(HookSlot&, HookEndpoint replacement) noexcept = 0;
    // Reverted and true abort guarantee no future write through a retained
    // slot address. A backend unable to prove this must report uncertainty.
    virtual HookCommit commit() noexcept = 0;
    virtual bool abort() noexcept = 0;
};

enum class HookStatus : std::uint8_t {
    Applied, NoChange, InvalidSpec, DuplicateRole, CapacityExceeded,
    BeginRejected, OperationRejected, CommitReverted, Uncertain, Poisoned
};

struct HookSnapshot {
    HookRole role;
    HookEndpoint original;
    HookEndpoint target_word;
    HookEndpoint trampoline_word;
    // Diagnostic address of the generic mirror only. A native backend can
    // use a separate pointer-typed Detours slot. It becomes stale after
    // detach_all(); never dereference or retain it as an owned handle.
    std::uintptr_t target_word_storage_address;
};

class HookTransactions final {
public:
    static constexpr std::size_t max_hooks = 256;
    explicit HookTransactions(HookBackend& backend) noexcept : backend_(backend) {}
    ~HookTransactions() noexcept;
    HookTransactions(const HookTransactions&) = delete;
    HookTransactions& operator=(const HookTransactions&) = delete;

    HookStatus install(const std::vector<HookSpec>& specs);
    HookStatus detach_all() noexcept;
    std::size_t size() const noexcept { return active_.size(); }
    bool poisoned() const noexcept { return poisoned_; }
    std::optional<HookSnapshot> snapshot(HookRole role) const noexcept;

private:
    struct Record { HookRole role; HookEndpoint replacement; HookSlot* slot; };
    void release(std::vector<Record>& records) noexcept;
    HookBackend& backend_;
    std::vector<Record> active_;
    std::vector<Record> retained_;
    bool poisoned_{};
};

// Deterministic test double. It writes the optional trampoline word during
// attach and retains &target_word until commit, like the linked Detours path.
// It never dereferences a real game address or patches process memory.
class MockDeferredHookBackend final : public HookBackend {
public:
    HookSlot& reserve_slot(HookEndpoint target) override;
    void release_slot(HookSlot&) noexcept override;
    HookBegin begin() noexcept override;
    bool attach(HookSlot&, HookEndpoint replacement) noexcept override;
    bool detach(HookSlot&, HookEndpoint replacement) noexcept override;
    HookCommit commit() noexcept override;
    bool abort() noexcept override;

    void reject_next_begin() noexcept { reject_begin_ = true; }
    void reject_attach_call(std::size_t n) noexcept { reject_attach_at_ = n; }
    void reject_detach_call(std::size_t n) noexcept { reject_detach_at_ = n; }
    void revert_next_commit() noexcept { revert_commit_ = true; }
    std::size_t slot_count() const noexcept { return slots_.size(); }
    std::size_t pending_count() const noexcept { return pending_count_; }
    bool transaction_open() const noexcept { return transaction_open_; }
    std::size_t last_commit_write_count() const noexcept { return last_commit_write_count_; }
    std::uintptr_t last_commit_write_address(std::size_t i) const noexcept;
    HookEndpoint last_commit_old_value(std::size_t i) const noexcept;
    HookEndpoint last_commit_new_value(std::size_t i) const noexcept;

private:
    struct Pending {
        HookEndpoint* target_word{};
        HookEndpoint next_value{};
    };
    std::vector<std::unique_ptr<HookSlot>> slots_;
    std::array<Pending, HookTransactions::max_hooks> pending_{};
    std::array<std::uintptr_t, HookTransactions::max_hooks> last_commit_addresses_{};
    std::array<HookEndpoint, HookTransactions::max_hooks> last_commit_old_values_{};
    std::array<HookEndpoint, HookTransactions::max_hooks> last_commit_new_values_{};
    std::size_t pending_count_{};
    std::size_t last_commit_write_count_{};
    std::size_t attach_calls_{};
    std::size_t detach_calls_{};
    std::size_t reject_attach_at_{};
    std::size_t reject_detach_at_{};
    HookEndpoint next_trampoline_ = 0x1000;
    bool transaction_open_{};
    bool reject_begin_{};
    bool revert_commit_{};
};

} // namespace fc
