#include "fc/records.hpp"

#include <algorithm>

namespace fc {
namespace {

const char* boundary_message(UnsupportedBoundary boundary) noexcept {
    switch (boundary) {
    case UnsupportedBoundary::FirstDeathIndex:
        return "original first death index enters a failure call";
    case UnsupportedBoundary::SecondDeathIndex:
        return "original second death index enters opaque overlap bytes";
    case UnsupportedBoundary::LargeStorageMetadata:
        return "original large storage metadata path cannot be represented";
    }
    return "unsupported original path";
}

void written(RecordEffects& effects, ObservedField field, std::size_t slot,
             std::uint64_t value) {
    effects.observed_write(field, slot, value);
}

void clear_table(RecordBank& bank, RecordEffects& effects) {
    bank.table.fill(0);
    written(effects, ObservedField::TableFill, 0, 0);
}

void reset_eligible_records(RecordBank& bank, RecordEffects& effects) {
    for (std::size_t i = 0; i < RecordBank::slot_count; ++i) {
        if (bank.records[i].word_10 != 0) reset_record(bank, i, effects);
    }
}

} // namespace

UnsupportedOriginalPath::UnsupportedOriginalPath(UnsupportedBoundary boundary)
    : std::runtime_error(boundary_message(boundary)), boundary_(boundary) {}

void reset_record(RecordBank& bank, std::size_t slot, RecordEffects& effects) {
    if (slot >= RecordBank::slot_count) throw std::out_of_range("record slot outside 0..64");
    auto& record = bank.records[slot];
    if (record.storage_token != 0 && record.count > record.entries.size()) {
        throw std::invalid_argument("record count exceeds supplied storage entries");
    }

    if (record.word_10 != 0) {
        record.word_0c = 0;
        written(effects, ObservedField::RecordWord0c, slot, 0);
        record.word_10 = 0;
        written(effects, ObservedField::RecordWord10, slot, 0);
    }

    if (record.storage_token != 0) {
        // The native helper visits count-1 down to 0, skipping null entries.
        for (std::uint32_t remaining = record.count; remaining != 0; --remaining) {
            const auto token = record.entries[remaining - 1];
            if (token != 0) effects.release_entry(token, 0xf0c0, 0x20);
        }

        // Native x86 SHL uses 32-bit arithmetic. The bounded representation
        // still requires count <= entries.size(), so no backing memory is read
        // outside the authored token list.
        const auto bytes = static_cast<std::uint32_t>(record.count << 2);
        if (bytes < 0x1000) {
            effects.release_storage(record.storage_token, bytes);
        } else {
            if (!record.large_storage || record.large_storage->allocation_base == 0 ||
                record.large_storage->header_distance >= 0x20) {
                throw UnsupportedOriginalPath(UnsupportedBoundary::LargeStorageMetadata);
            }
            effects.release_storage(record.large_storage->allocation_base,
                                    static_cast<std::uint32_t>(bytes + 0x23));
        }
    }

    record.count = 0;
    written(effects, ObservedField::RecordCount, slot, 0);
    record.storage_token = 0;
    written(effects, ObservedField::RecordStorage, slot, 0);
    record.entries.clear();
    record.large_storage.reset();
}

void selected_round_start_cleanup(RecordBank& bank, RecordEffects& effects) {
    reset_eligible_records(bank, effects);
    clear_table(bank, effects);

    auto& aux = bank.auxiliary;
    aux.byte_a = 0;
    written(effects, ObservedField::ByteA, 0, 0);
    aux.byte_b = 0;
    written(effects, ObservedField::ByteB, 0, 0);
    aux.word_a = 0;
    written(effects, ObservedField::WordA, 0, 0);
    aux.word_b = 0;
    written(effects, ObservedField::WordB, 0, 0);
    aux.byte_c = 0;
    written(effects, ObservedField::ByteC, 0, 0);
    aux.phase_byte = 1;
    written(effects, ObservedField::PhaseByte, 0, 1);
}

DeathCleanupResult selected_death_cleanup(RecordBank& bank, ResourceToken victim_identity,
                                         LocalIdentityProvider& local_provider,
                                         DeathIndexProvider& indices, RecordEffects& effects) {
    const auto local = local_provider.reread_local_identity();
    if (victim_identity == local) {
        reset_eligible_records(bank, effects);
        bank.auxiliary.phase_byte = 1;
        written(effects, ObservedField::PhaseByte, 0, 1);
        clear_table(bank, effects);
        return DeathCleanupResult::LocalFullReset;
    }
    if (victim_identity == 0) return DeathCleanupResult::NoSelectedEffect;

    const auto first = indices.next_index();
    if (first >= RecordBank::slot_count) {
        throw UnsupportedOriginalPath(UnsupportedBoundary::FirstDeathIndex);
    }
    bank.table[first] = 0;
    written(effects, ObservedField::TableWord, first, 0);

    const auto second = indices.next_index();
    if (second >= RecordBank::slot_count) {
        throw UnsupportedOriginalPath(UnsupportedBoundary::SecondDeathIndex);
    }
    if (bank.records[second].word_10 != 0) reset_record(bank, second, effects);
    return DeathCleanupResult::NonlocalSelectedEffect;
}

} // namespace fc
