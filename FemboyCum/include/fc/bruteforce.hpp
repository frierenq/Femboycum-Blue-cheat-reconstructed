#pragma once
#include <array>
#include <cstdint>
#include <memory>
#include <optional>

namespace fc {
// Only the two recovered 65-word regions; this is not the native context layout.
struct BruteforceState {
    std::array<std::uint32_t, 65> reference{};
    std::array<std::uint32_t, 65> selected{};
};
static_assert(sizeof(BruteforceState) == 0x208);
enum class StateBank { Reference, Selected };
class EntitySlot {
public:
    static EntitySlot checked(std::uint32_t value);
    std::uint32_t value() const noexcept { return value_; }
private:
    explicit EntitySlot(std::uint32_t value) : value_(value) {}
    std::uint32_t value_;
};
class RecordSlot {
public:
    static RecordSlot checked(std::uint32_t value);
    EntitySlot entity_slot() const { return EntitySlot::checked(value_ + 1); }
    std::uint32_t value() const noexcept { return value_; }
private:
    explicit RecordSlot(std::uint32_t value) : value_(value) {}
    std::uint32_t value_;
};
using StateContext = std::shared_ptr<BruteforceState>;
class BruteforceStore {
public:
    virtual ~BruteforceStore() = default;
    virtual StateContext acquire() = 0;
    virtual std::uint32_t read(const StateContext&, StateBank, EntitySlot) = 0;
    virtual void write(const StateContext&, StateBank, EntitySlot, std::uint32_t) = 0;
};
class OwnedBruteforceStore final : public BruteforceStore {
public:
    OwnedBruteforceStore();
    StateContext acquire() override;
    std::uint32_t read(const StateContext&, StateBank, EntitySlot) override;
    void write(const StateContext&, StateBank, EntitySlot, std::uint32_t) override;
    void replace(StateContext);
private:
    StateContext current_;
};
class RandomSource {
public:
    virtual ~RandomSource() = default;
    virtual std::int32_t integer(std::int32_t low, std::int32_t high) = 0;
};
struct FeedbackTiming {
    float stored_time;
    float counter_multiplier;
    std::int32_t counter;
};
// These entry points assume the containing native gates have already been reached.
// They do not assert event eligibility or reproduce the unresolved engine callbacks.
void recovered_hurt_tail(BruteforceStore&, RandomSource&, EntitySlot second_index);
void recovered_feedback_tail(BruteforceStore&, RecordSlot reloaded_index,
                             std::optional<FeedbackTiming>);
void recovered_array_reset(BruteforceState&) noexcept;
std::optional<float> recovered_per_entity_sign(std::uint32_t selected) noexcept;
}
