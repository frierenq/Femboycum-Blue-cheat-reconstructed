#include "fc/bruteforce.hpp"
#include <cmath>
#include <bit>
#include <deque>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
unsigned checks{};
void require(bool condition, const char* message) {
    ++checks;
    if (!condition) throw std::runtime_error(message);
}
struct Store final : fc::BruteforceStore {
    fc::StateContext first = std::make_shared<fc::BruteforceState>();
    fc::StateContext second = std::make_shared<fc::BruteforceState>();
    fc::StateContext third = std::make_shared<fc::BruteforceState>();
    std::deque<fc::StateContext> acquisitions;
    std::vector<std::string> operations;
    unsigned id(const fc::StateContext& context) const { return context == first ? 1 : context == second ? 2 : 3; }
    std::string key(const fc::StateContext& context, fc::StateBank bank, fc::EntitySlot slot) const {
        return std::to_string(id(context)) + (bank == fc::StateBank::Reference ? ":r:" : ":s:") + std::to_string(slot.value());
    }
    fc::StateContext acquire() override {
        auto result = first;
        if (!acquisitions.empty()) { result = acquisitions.front(); acquisitions.pop_front(); }
        operations.push_back("acquire:" + std::to_string(id(result)));
        return result;
    }
    std::uint32_t read(const fc::StateContext& context, fc::StateBank bank, fc::EntitySlot slot) override {
        const auto result = (bank == fc::StateBank::Reference ? context->reference : context->selected)[slot.value()];
        operations.push_back("read:" + key(context, bank, slot) + ":" + std::to_string(result));
        return result;
    }
    void write(const fc::StateContext& context, fc::StateBank bank, fc::EntitySlot slot, std::uint32_t value) override {
        operations.push_back("write:" + key(context, bank, slot) + ":" + std::to_string(value));
        (bank == fc::StateBank::Reference ? context->reference : context->selected)[slot.value()] = value;
    }
};
struct Random final : fc::RandomSource {
    std::int32_t word = 1;
    Store* store{};
    unsigned calls{};
    std::int32_t integer(std::int32_t low, std::int32_t high) override {
        require(low == 1 && high == 2, "exact RNG arguments");
        ++calls;
        if (store) store->operations.push_back("random:" + std::to_string(word));
        return word;
    }
};
int probe() {
    std::string kind;
    while (std::cin >> kind) {
        Store store;
        Random random;
        random.store = &store;
        unsigned slot{}, reloads{};
        std::uint32_t r1{}, s1{}, r2{}, s2{}, r3{}, s3{};
        if (!(std::cin >> slot >> random.word >> r1 >> s1 >> r2 >> s2 >> r3 >> s3 >> reloads) || reloads > 3)
            throw std::invalid_argument("invalid differential probe input");
        const auto entity = fc::EntitySlot::checked(slot);
        const std::array<fc::StateContext, 3> contexts{store.first, store.second, store.third};
        for (unsigned i = 0; i < reloads; ++i) {
            unsigned id{};
            if (!(std::cin >> id) || id < 1 || id > 3) throw std::invalid_argument("invalid context sequence");
            store.acquisitions.push_back(contexts[id - 1]);
        }
        store.first->reference[slot] = r1; store.first->selected[slot] = s1;
        store.second->reference[slot] = r2; store.second->selected[slot] = s2;
        store.third->reference[slot] = r3; store.third->selected[slot] = s3;
        if (kind == "hurt") fc::recovered_hurt_tail(store, random, entity);
        else if (kind == "feedback") {
            unsigned has_timing{};
            std::uint32_t stored{}, multiplier{};
            std::int32_t counter{};
            if (!(std::cin >> has_timing >> stored >> multiplier >> counter) || has_timing > 1 || !slot)
                throw std::invalid_argument("invalid feedback probe input");
            std::optional<fc::FeedbackTiming> timing;
            if (has_timing) timing = fc::FeedbackTiming{std::bit_cast<float>(stored), std::bit_cast<float>(multiplier), counter};
            fc::recovered_feedback_tail(store, fc::RecordSlot::checked(slot - 1), timing);
        }
        else throw std::invalid_argument("unsupported differential probe kind");
        std::cout << "{\"reference\":[" << store.first->reference[slot] << ',' << store.second->reference[slot] << ',' << store.third->reference[slot]
                  << "],\"selected\":[" << store.first->selected[slot] << ',' << store.second->selected[slot] << ',' << store.third->selected[slot]
                  << "],\"trace\":[";
        for (std::size_t i = 0; i < store.operations.size(); ++i) {
            if (i) std::cout << ',';
            std::cout << '"' << store.operations[i] << '"';
        }
        std::cout << "]}\n";
    }
    if (!std::cin.eof()) throw std::invalid_argument("incomplete differential probe input");
    return 0;
}
}
int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "--probe") return probe();
        for (std::uint32_t reference : {0u, 1u, 2u, 3u, 0xffffffffu}) {
            for (std::uint32_t selected : {0u, 1u, 2u, 3u, 0xffffffffu}) {
                for (std::int32_t word : {1, 2, -1}) {
                    Store store;
                    Random random;
                    random.word = word;
                    random.store = &store;
                    store.first->reference[64] = reference;
                    store.first->selected[64] = selected;
                    fc::recovered_hurt_tail(store, random, fc::EntitySlot::checked(64));
                    const auto intermediate = reference == 1 ? 2u : reference == 2 ? 1u : 0u;
                    const auto before_second = reference ? intermediate : selected;
                    const auto expected = before_second == 0 ? static_cast<std::uint32_t>(word)
                        : before_second == 1 ? 2u : before_second == 2 ? 1u : 0u;
                    require(store.first->selected[64] == expected && store.first->reference[64] == reference, "hurt state table");
                    require(random.calls == unsigned(before_second == 0), "only zero selected calls RNG");
                    require(store.first->selected[0] == 0, "other slot untouched");
                }
            }
        }
        {
            Store store;
            Random random;
            random.store = &store;
            store.first->reference[1] = 3;
            store.first->selected[1] = 99;
            store.second->selected[1] = 0;
            store.third->selected[1] = 88;
            store.acquisitions = {store.first, store.second, store.third};
            fc::recovered_hurt_tail(store, random, fc::EntitySlot::checked(1));
            require(store.operations == std::vector<std::string>({
                "acquire:1", "read:1:r:1:3", "write:1:s:1:0", "acquire:2", "read:2:s:1:0", "random:1", "acquire:3", "write:3:s:1:1"
            }), "full intermediate write and context reload trace");
        }
        {
            Store store;
            Random random;
            store.first->reference[0] = 1;
            store.first->selected[0] = 99;
            store.second->selected[0] = 2;
            store.acquisitions = {store.first, store.second};
            fc::recovered_hurt_tail(store, random, fc::EntitySlot::checked(0));
            require(store.first->selected[0] == 2 && store.second->selected[0] == 1 && random.calls == 0,
                    "second index zero remains supported and later context controls final read/write");
        }
        for (const auto old : {0u, 1u, 2u, 3u, 0xffffffffu}) {
            for (const auto index : {0u, 63u}) {
                Store store;
                const auto expected = old == 0 ? 1u : old == 1 ? 2u : old == 2 ? 1u : 0u;
                store.first->selected[index + 1] = old;
                store.first->reference[index + 1] = 99;
                fc::recovered_feedback_tail(store, fc::RecordSlot::checked(index), std::nullopt);
                require(store.first->selected[index + 1] == expected && store.first->reference[index + 1] == 99,
                        "feedback null result selects exact record alias");
            }
        }
        for (const auto stored : {10.0f, std::nextafter(10.25f, 10.0f), 10.25f, 9.75f,
                                   std::numeric_limits<float>::quiet_NaN(), std::numeric_limits<float>::infinity()}) {
            Store store;
            fc::recovered_feedback_tail(store, fc::RecordSlot::checked(0), fc::FeedbackTiming{stored, 1.0f / 64.0f, 640});
            const bool reference = std::isnan(stored) || std::fabs(stored - 10.0f) < 0.25f;
            require(store.first->reference[1] == unsigned(reference) && store.first->selected[1] == unsigned(!reference),
                    "strict threshold/equality/NaN routing");
        }
        {
            fc::BruteforceState state;
            state.reference.fill(99);
            state.selected.fill(88);
            fc::recovered_array_reset(state);
            for (unsigned i = 0; i < 65; ++i)
                require(state.reference[i] == 0 && state.selected[i] == 0, "exact two65-slot reset spans");
        }
        require(!fc::recovered_per_entity_sign(0), "zero leaves per-entity route");
        require(fc::recovered_per_entity_sign(1) == -60.0f && fc::recovered_per_entity_sign(99) == 60.0f, "selected state sign projection");
        bool invalid_entity{}, invalid_record{};
        try { (void)fc::EntitySlot::checked(65); } catch (const std::invalid_argument&) { invalid_entity = true; }
        try { (void)fc::RecordSlot::checked(64); } catch (const std::invalid_argument&) { invalid_record = true; }
        require(invalid_entity && invalid_record, "explicit owned-index support boundary");
        std::cout << "{\"passed\":true,\"checks\":" << checks << ",\"owned_slots_per_bank\":65,\"whole_feature_recovered\":false}\n";
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
