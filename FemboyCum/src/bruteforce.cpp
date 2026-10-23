#include "fc/bruteforce.hpp"
#include <cmath>
#include <emmintrin.h>
#include <stdexcept>
#include <utility>

namespace fc {
namespace {
StateContext current(BruteforceStore& store) {
    auto result = store.acquire();
    if (!result) throw std::logic_error("recovered tail has no owned context");
    return result;
}
auto& bank(const StateContext& context, StateBank which) {
    if (!context) throw std::invalid_argument("null owned context");
    return which == StateBank::Reference ? context->reference : context->selected;
}
}
EntitySlot EntitySlot::checked(std::uint32_t value) {
    if (value > 64) throw std::invalid_argument("owned entity slot must be in 0..64");
    return EntitySlot(value);
}
RecordSlot RecordSlot::checked(std::uint32_t value) {
    if (value > 63) throw std::invalid_argument("owned feedback slot must be in 0..63");
    return RecordSlot(value);
}
OwnedBruteforceStore::OwnedBruteforceStore() : current_(std::make_shared<BruteforceState>()) {}
StateContext OwnedBruteforceStore::acquire() { return current_; }
std::uint32_t OwnedBruteforceStore::read(const StateContext& context, StateBank which, EntitySlot slot) {
    return bank(context, which)[slot.value()];
}
void OwnedBruteforceStore::write(const StateContext& context, StateBank which, EntitySlot slot, std::uint32_t value) {
    bank(context, which)[slot.value()] = value;
}
void OwnedBruteforceStore::replace(StateContext state) {
    if (!state) throw std::invalid_argument("cannot publish null owned context");
    current_ = std::move(state);
}
void recovered_hurt_tail(BruteforceStore& store, RandomSource& random, EntitySlot slot) {
    auto context = current(store);
    const auto reference = store.read(context, StateBank::Reference, slot);
    if (reference) {
        const auto intermediate = reference == 1 ? 2u : (reference == 2 ? 1u : 0u);
        store.write(context, StateBank::Selected, slot, intermediate);
        context = current(store);
    }
    const auto selected = store.read(context, StateBank::Selected, slot);
    if (!selected) {
        // Preserve all bits returned by the shared external RNG, without a local seed or clamp.
        const auto next = static_cast<std::uint32_t>(random.integer(1, 2));
        context = current(store);
        store.write(context, StateBank::Selected, slot, next);
    } else {
        const auto next = selected == 1 ? 2u : (selected == 2 ? 1u : 0u);
        store.write(context, StateBank::Selected, slot, next);
    }
}
void recovered_feedback_tail(BruteforceStore& store, RecordSlot record,
                              std::optional<FeedbackTiming> timing) {
    bool reference = false;
    if (timing) {
        const auto count = _mm_cvtsi32_ss(_mm_setzero_ps(), timing->counter);
        const auto clock = _mm_mul_ss(_mm_set_ss(timing->counter_multiplier), count);
        const auto difference = _mm_sub_ss(_mm_set_ss(timing->stored_time), clock);
        const auto magnitude = _mm_and_ps(difference, _mm_castsi128_ps(_mm_set1_epi32(0x7fffffff)));
        const auto delta = _mm_cvtss_f32(magnitude);
        reference = std::isnan(delta) || delta < 0.25f;
    }
    const auto context = current(store);
    const auto which = reference ? StateBank::Reference : StateBank::Selected;
    const auto slot = record.entity_slot();
    const auto old = store.read(context, which, slot);
    constexpr std::array<std::uint32_t, 3> transitions{1, 2, 1};
    store.write(context, which, slot, old <= 2 ? transitions[old] : 0u);
}
void recovered_array_reset(BruteforceState& state) noexcept {
    // Verified bounded fill clears native [context+0xa0, context+0x2a8).
    state.reference.fill(0);
    state.selected.fill(0);
}
std::optional<float> recovered_per_entity_sign(std::uint32_t selected) noexcept {
    if (!selected) return std::nullopt;
    return selected == 1 ? -60.0f : 60.0f;
}
}
