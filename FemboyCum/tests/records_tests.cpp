#include "fc/records.hpp"

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {
using namespace fc;

void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

const char* field_name(ObservedField field) {
    switch (field) {
    case ObservedField::RecordWord0c: return "0c";
    case ObservedField::RecordWord10: return "10";
    case ObservedField::RecordCount: return "count";
    case ObservedField::RecordStorage: return "storage";
    case ObservedField::TableWord: return "table";
    case ObservedField::TableFill: return "table-fill";
    case ObservedField::ByteA: return "byte-a";
    case ObservedField::ByteB: return "byte-b";
    case ObservedField::WordA: return "word-a";
    case ObservedField::WordB: return "word-b";
    case ObservedField::ByteC: return "byte-c";
    case ObservedField::PhaseByte: return "phase";
    }
    throw std::runtime_error("unknown field");
}

struct Recorder final : RecordEffects {
    RecordBank& bank;
    explicit Recorder(RecordBank& value) : bank(value) {}
    std::vector<std::string> actions;
    std::vector<std::pair<std::uint32_t, std::uint32_t>> released_state;
    void observed_write(ObservedField field, std::size_t slot, std::uint64_t value) override {
        actions.emplace_back(std::string("write:") + field_name(field) + ":" +
                             std::to_string(slot) + ":" + std::to_string(value));
    }
    void release_entry(ResourceToken token, std::uint32_t a, std::uint32_t b) override {
        check(a == 0xf0c0 && b == 0x20, "entry release literal arguments changed");
        released_state.emplace_back(bank.records[0].word_0c, bank.records[0].word_10);
        actions.emplace_back("entry:" + std::to_string(token));
    }
    void release_storage(ResourceToken token, std::uint32_t bytes) override {
        actions.emplace_back("storage:" + std::to_string(token) + ":" + std::to_string(bytes));
    }
};

struct Indices final : DeathIndexProvider {
    std::vector<std::uint32_t> values;
    std::size_t calls{};
    std::vector<std::string>* call_order{};
    explicit Indices(std::vector<std::uint32_t> given) : values(std::move(given)) {}
    std::uint32_t next_index() override {
        if (calls == values.size()) throw std::runtime_error("unexpected index callback");
        if (call_order) call_order->push_back("index");
        return values[calls++];
    }
};

struct Local final : LocalIdentityProvider {
    ResourceToken value;
    std::size_t calls{};
    std::vector<std::string>* call_order{};
    explicit Local(ResourceToken given) : value(given) {}
    ResourceToken reread_local_identity() override {
        if (call_order) call_order->push_back("local");
        ++calls;
        return value;
    }
};

void check_trace(const Recorder& effects, std::vector<std::string> expected, const char* context) {
    if (effects.actions == expected) return;
    std::cerr << context << " trace mismatch\n";
    for (const auto& action : effects.actions) std::cerr << "  " << action << '\n';
    throw std::runtime_error(context);
}

void helper_release_order_and_null_entries() {
    RecordBank bank;
    auto& record = bank.records[0];
    record.word_0c = 7;
    record.word_10 = 9;
    record.storage_token = 100;
    record.count = 4;
    record.entries = {11, 0, 22, 33};
    Recorder effects(bank);
    reset_record(bank, 0, effects);
    check_trace(effects, {"write:0c:0:0", "write:10:0:0", "entry:33", "entry:22",
                          "entry:11", "storage:100:16", "write:count:0:0",
                          "write:storage:0:0"}, "helper release order");
    check(effects.released_state.size() == 3, "wrong number of entry releases");
    for (const auto& [word_0c, word_10] : effects.released_state) {
        check(word_0c == 0 && word_10 == 0, "record words must clear before releases");
    }
    check(record.storage_token == 0 && record.count == 0 && record.entries.empty(),
          "owned storage not cleared");
}

void helper_null_and_zero_word_cases() {
    RecordBank bank;
    auto& record = bank.records[0];
    record.word_0c = 21;
    record.word_10 = 0;
    record.storage_token = 90;
    record.count = 0;
    Recorder effects(bank);
    reset_record(bank, 0, effects);
    check_trace(effects, {"storage:90:0", "write:count:0:0", "write:storage:0:0"},
                "zero-word helper");
    check(record.word_0c == 21, "zero word_10 should leave word_0c untouched");

    record.word_0c = 17;
    record.word_10 = 5;
    record.storage_token = 0;
    record.count = 8; // null storage pointer still reaches final count write
    effects.actions.clear();
    reset_record(bank, 0, effects);
    check_trace(effects, {"write:0c:0:0", "write:10:0:0", "write:count:0:0",
                          "write:storage:0:0"}, "null storage helper");
}

void large_storage_and_partial_failure() {
    RecordBank bank;
    auto& record = bank.records[0];
    record.storage_token = 500;
    record.count = 1024;
    record.entries.assign(1024, 0);
    record.entries[0] = 42;
    record.word_0c = 8;
    record.word_10 = 9;
    record.large_storage = LargeStorageMetadata{400, 31};
    Recorder effects(bank);
    reset_record(bank, 0, effects);
    check_trace(effects, {"write:0c:0:0", "write:10:0:0", "entry:42",
                          "storage:400:4131", "write:count:0:0", "write:storage:0:0"},
                "large storage helper");

    record.storage_token = 500;
    record.count = 1024;
    record.entries.assign(1024, 0);
    record.entries[1023] = 77;
    record.word_0c = 8;
    record.word_10 = 9;
    record.large_storage = LargeStorageMetadata{400, 32};
    effects.actions.clear();
    bool caught = false;
    try {
        reset_record(bank, 0, effects);
    } catch (const UnsupportedOriginalPath& error) {
        caught = error.boundary() == UnsupportedBoundary::LargeStorageMetadata;
    }
    check(caught, "invalid large metadata should be an explicit unsupported path");
    check_trace(effects, {"write:0c:0:0", "write:10:0:0", "entry:77"},
                "large metadata partial effects");
    check(record.count == 1024 && record.storage_token == 500 && record.word_10 == 0,
          "partial helper effects were rolled back or overextended");
}

void round_start_order_and_two_events() {
    RecordBank bank;
    bank.records[0].word_10 = 1;
    bank.records[0].word_0c = 10;
    bank.records[64].word_10 = 2;
    bank.records[64].word_0c = 20;
    bank.table.fill(9);
    bank.auxiliary = {1, 2, 3, 4, 5, 6};
    Recorder effects(bank);
    selected_round_start_cleanup(bank, effects);
    check_trace(effects, {"write:0c:0:0", "write:10:0:0", "write:count:0:0",
                          "write:storage:0:0", "write:0c:64:0", "write:10:64:0",
                          "write:count:64:0", "write:storage:64:0", "write:table-fill:0:0",
                          "write:byte-a:0:0", "write:byte-b:0:0", "write:word-a:0:0",
                          "write:word-b:0:0", "write:byte-c:0:0", "write:phase:0:1"},
                "round start order");
    for (auto value : bank.table) check(value == 0, "round table not fully cleared");
    check(bank.auxiliary.phase_byte == 1, "round phase byte wrong");

    // A second round still emits the unconditional table/auxiliary writes,
    // but records with word_10 already zero do not enter the helper.
    effects.actions.clear();
    selected_round_start_cleanup(bank, effects);
    check_trace(effects, {"write:table-fill:0:0", "write:byte-a:0:0", "write:byte-b:0:0",
                          "write:word-a:0:0", "write:word-b:0:0", "write:byte-c:0:0",
                          "write:phase:0:1"}, "second round");
}

void death_routes_and_repeated_index() {
    RecordBank bank;
    bank.table.fill(7);
    bank.records[9].word_0c = 12;
    bank.records[9].word_10 = 13;
    Recorder effects(bank);
    Local local(100);
    Indices indices({7, 9});
    std::vector<std::string> call_order;
    local.call_order = &call_order;
    indices.call_order = &call_order;
    auto result = selected_death_cleanup(bank, 200, local, indices, effects);
    check(result == DeathCleanupResult::NonlocalSelectedEffect, "nonlocal result wrong");
    check(local.calls == 1 && indices.calls == 2, "identity/index callback counts wrong");
    check(call_order == std::vector<std::string>({"local", "index", "index"}),
          "identity reload must precede the two distinct index calls");
    check_trace(effects, {"write:table:7:0", "write:0c:9:0", "write:10:9:0",
                          "write:count:9:0", "write:storage:9:0"},
                "nonlocal death with differing indices");
    check(bank.table[7] == 0 && bank.table[9] == 7,
          "first callback must select table, second callback must select record");

    // Local death follows the nonlocal event and resets all eligible records.
    bank.records[1].word_10 = 5;
    bank.records[64].word_10 = 6;
    effects.actions.clear();
    call_order.clear();
    local.value = 200;
    auto local_result = selected_death_cleanup(bank, 200, local, indices, effects);
    check(local_result == DeathCleanupResult::LocalFullReset, "local result wrong");
    check(indices.calls == 2, "local death should not request an index");
    check(call_order == std::vector<std::string>({"local"}),
          "local death should only re-read identity");
    check(effects.actions.front() == "write:0c:1:0" &&
          effects.actions[4] == "write:0c:64:0" &&
          effects.actions[8] == "write:phase:0:1" &&
          effects.actions[9] == "write:table-fill:0:0", "local death order wrong");

    effects.actions.clear();
    Local nonzero_local(100);
    Indices unused({});
    auto skipped = selected_death_cleanup(bank, 0, nonzero_local, unused, effects);
    check(skipped == DeathCleanupResult::NoSelectedEffect && effects.actions.empty(),
          "null victim against nonnull local should skip selected writes");

    // The native comparison also treats two zero identities as equal.
    bank.table.fill(4);
    Local zero_local(0);
    auto both_zero = selected_death_cleanup(bank, 0, zero_local, unused, effects);
    check(both_zero == DeathCleanupResult::LocalFullReset && bank.table[64] == 0,
          "both-zero local equality was lost");
}

void death_unsupported_boundaries_preserve_partial_effects() {
    RecordBank bank;
    bank.table.fill(8);
    bank.records[9].word_10 = 5;
    Recorder effects(bank);
    Local local(100);
    Indices bad_first({65});
    bool caught = false;
    try { (void)selected_death_cleanup(bank, 200, local, bad_first, effects); }
    catch (const UnsupportedOriginalPath& error) {
        caught = error.boundary() == UnsupportedBoundary::FirstDeathIndex;
    }
    check(caught && bad_first.calls == 1 && effects.actions.empty() && bank.table[7] == 8,
          "first bad index must stop before selected writes");

    Indices bad_second({7, 65});
    caught = false;
    try { (void)selected_death_cleanup(bank, 200, local, bad_second, effects); }
    catch (const UnsupportedOriginalPath& error) {
        caught = error.boundary() == UnsupportedBoundary::SecondDeathIndex;
    }
    check(caught && bad_second.calls == 2, "second bad index was not observed");
    check_trace(effects, {"write:table:7:0"}, "second bad index partial effects");
    check(bank.table[7] == 0 && bank.records[9].word_10 == 5,
          "second bad index should retain table write but skip record reset");
}

void malformed_authored_storage_is_rejected_before_writes() {
    RecordBank bank;
    auto& record = bank.records[0];
    record.word_10 = 1;
    record.storage_token = 10;
    record.count = 2;
    record.entries = {20};
    Recorder effects(bank);
    bool caught = false;
    try { reset_record(bank, 0, effects); }
    catch (const std::invalid_argument&) { caught = true; }
    check(caught && effects.actions.empty() && record.word_10 == 1,
          "authored backing-storage precondition should fail before writes");
}
} // namespace

int main() {
    try {
        helper_release_order_and_null_entries();
        helper_null_and_zero_word_cases();
        large_storage_and_partial_failure();
        round_start_order_and_two_events();
        death_routes_and_repeated_index();
        death_unsupported_boundaries_preserve_partial_effects();
        malformed_authored_storage_is_rejected_before_writes();
        std::cout << "records selected-tail tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
