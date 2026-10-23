#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <vector>

namespace fc {

// Opaque analyst tokens. Zero represents a null native pointer; no token is
// dereferenced or automatically freed by the source-owned model.
using ResourceToken = std::uint64_t;

struct LargeStorageMetadata {
    ResourceToken allocation_base{};
    std::uint32_t header_distance{};
};

// Only fields observed in 0x412e9e30. This is not the native 0x10940 layout.
struct RecordSlice {
    ResourceToken storage_token{};       // native +4
    std::uint32_t count{};               // native +8
    std::uint32_t word_0c{};             // native +0x0c
    std::uint32_t word_10{};             // native +0x10
    std::vector<ResourceToken> entries; // supplied contents of storage_token
    std::optional<LargeStorageMetadata> large_storage;
};

// Analyst labels for six directly observed event fields, in native write
// order. Their addresses are mapped in research/checkpoint-24/record-lifecycle.
struct AuxiliaryEventFields {
    std::uint8_t byte_a{};
    std::uint8_t byte_b{};
    std::uint32_t word_a{};
    std::uint32_t word_b{};
    std::uint8_t byte_c{};
    std::uint8_t phase_byte{};
};

struct RecordBank {
    static constexpr std::size_t slot_count = 65;
    std::array<RecordSlice, slot_count> records;
    std::array<std::uint32_t, slot_count> table{};
    AuxiliaryEventFields auxiliary;
};

enum class ObservedField {
    RecordWord0c, RecordWord10, RecordCount, RecordStorage,
    TableWord, TableFill, ByteA, ByteB, WordA, WordB, ByteC, PhaseByte
};

class RecordEffects {
public:
    virtual ~RecordEffects() = default;
    // Notifications follow each corresponding typed write. Callbacks must
    // return normally and must not reenter the bank.
    virtual void observed_write(ObservedField field, std::size_t record_or_slot,
                                std::uint64_t value) = 0;
    virtual void release_entry(ResourceToken token, std::uint32_t literal_f0c0,
                               std::uint32_t literal_20) = 0;
    virtual void release_storage(ResourceToken token, std::uint32_t byte_size) = 0;
};

class DeathIndexProvider {
public:
    virtual ~DeathIndexProvider() = default;
    virtual std::uint32_t next_index() = 0;
};

class LocalIdentityProvider {
public:
    virtual ~LocalIdentityProvider() = default;
    virtual ResourceToken reread_local_identity() = 0;
};

enum class UnsupportedBoundary { FirstDeathIndex, SecondDeathIndex, LargeStorageMetadata };
class UnsupportedOriginalPath : public std::runtime_error {
public:
    explicit UnsupportedOriginalPath(UnsupportedBoundary boundary);
    UnsupportedBoundary boundary() const noexcept { return boundary_; }
private:
    UnsupportedBoundary boundary_;
};

enum class DeathCleanupResult { NoSelectedEffect, NonlocalSelectedEffect, LocalFullReset };

// Research-only selected tails. They do not establish original event
// eligibility, external object conversion, or common callback execution.
void reset_record(RecordBank&, std::size_t slot, RecordEffects&);
void selected_round_start_cleanup(RecordBank&, RecordEffects&);
DeathCleanupResult selected_death_cleanup(RecordBank&, ResourceToken victim_identity,
                                         LocalIdentityProvider&, DeathIndexProvider&,
                                         RecordEffects&);

} // namespace fc
