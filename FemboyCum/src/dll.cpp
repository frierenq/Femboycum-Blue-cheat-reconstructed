#include "fc/api.h"
#include "fc/mock.hpp"
#if defined(FC_ENABLE_LUAJIT_CANDIDATE)
#include "fc/lua_host.hpp"
#endif
#include <cstring>
#include <exception>
#include <memory>
#include <stdexcept>

struct fc_handle {
    fc::MockEngine engine;
    std::unique_ptr<fc::ScriptHost> scripts;
    fc::RecordingRenderer renderer;
    fc::Core core;
    std::string error;
    bool lua_candidate{};

    explicit fc_handle(bool candidate) :
#if defined(FC_ENABLE_LUAJIT_CANDIDATE)
        scripts(candidate ? std::unique_ptr<fc::ScriptHost>(std::make_unique<fc::LuaJitCandidateHost>())
                          : std::unique_ptr<fc::ScriptHost>(std::make_unique<fc::MockScripts>())),
#else
        scripts(std::make_unique<fc::MockScripts>()),
#endif
        core(engine, *scripts, renderer), lua_candidate(candidate) {
#if defined(FC_ENABLE_LUAJIT_CANDIDATE)
        if (candidate) static_cast<fc::LuaJitCandidateHost&>(*scripts).bind(core);
#endif
    }
};
namespace {
void store_error(fc_handle* h, const char* message) noexcept {
    try { h->error = message; } catch (...) { h->error.clear(); }
}
template<class Function> int guarded(fc_handle* h, Function function) noexcept {
    if (!h) return FC_INVALID_ARGUMENT;
    try { const int status = function(); h->error.clear(); return status; }
    catch (const fc::UnsupportedOriginalPath& e) { store_error(h, e.what()); return FC_UNSUPPORTED_ORIGINAL_PATH; }
    catch (const std::invalid_argument& e) { store_error(h, e.what()); return FC_INVALID_ARGUMENT; }
    catch (const std::logic_error& e) { store_error(h, e.what()); return FC_BAD_STATE; }
    catch (const std::exception& e) { store_error(h, e.what()); return FC_INTERNAL_ERROR; }
    catch (...) { store_error(h, "unknown native exception"); return FC_INTERNAL_ERROR; }
}
std::string_view bytes(const char* data, uint32_t size) {
    if ((!data && size) || size > fc::ConfigDocument::max_bytes)
        throw std::invalid_argument("invalid byte input");
    return size ? std::string_view(data, size) : std::string_view{};
}
int copy(const std::string& value, char* output, uint32_t capacity, uint32_t* required) {
    if (!required || (!output && capacity)) return FC_INVALID_ARGUMENT;
    *required = static_cast<uint32_t>(value.size() + 1);
    if (!output && !capacity) return FC_OK;
    if (capacity < *required) return FC_BUFFER_TOO_SMALL;
    std::memcpy(output, value.data(), value.size());
    output[value.size()] = '\0';
    return FC_OK;
}
}
extern "C" {
uint32_t fc_abi_version(void) { return 1; }
fc_handle* fc_create(void) { try { return new fc_handle(false); } catch (...) { return nullptr; } }
uint32_t fc_lua_candidate_available(void) {
#if defined(FC_ENABLE_LUAJIT_CANDIDATE)
    return 1;
#else
    return 0;
#endif
}
fc_handle* fc_create_lua_candidate(void) {
#if defined(FC_ENABLE_LUAJIT_CANDIDATE)
    try { return new fc_handle(true); } catch (...) { return nullptr; }
#else
    return nullptr;
#endif
}
void fc_destroy(fc_handle* h) { delete h; }
int fc_lua_load_research_script(fc_handle* h, const char* source, uint32_t size) {
    return guarded(h, [&]() -> int {
#if defined(FC_ENABLE_LUAJIT_CANDIDATE)
        if (!h->lua_candidate) throw std::logic_error("handle does not own Lua candidate host");
        static_cast<fc::LuaJitCandidateHost&>(*h->scripts).load_research_script(bytes(source, size));
        return FC_OK;
#else
        (void)source;
        (void)size;
        throw std::logic_error("Lua candidate host is disabled in this build");
#endif
    });
}
int fc_initialize(fc_handle* h, const char* config, uint32_t size) {
    return guarded(h, [&] { h->core.initialize(bytes(config, size)); return FC_OK; });
}
int fc_shutdown(fc_handle* h) { return guarded(h, [&] { h->core.shutdown(); return FC_OK; }); }
int fc_set_text(fc_handle* h, const char* text, uint32_t size) {
    return guarded(h, [&] { h->core.set_text(std::string(bytes(text, size))); return FC_OK; });
}
int fc_get_text(fc_handle* h, char* output, uint32_t capacity, uint32_t* required) {
    return guarded(h, [&] { return copy(h->core.text(), output, capacity, required); });
}
int fc_dispatch(fc_handle* h, const char* name, uint32_t size, uint64_t tick) {
    return guarded(h, [&] { h->core.dispatch({std::string(bytes(name, size)), tick}); return FC_OK; });
}
int fc_save(fc_handle* h, char* output, uint32_t capacity, uint32_t* required) {
    return guarded(h, [&] { return copy(h->core.save(), output, capacity, required); });
}
int fc_last_error(fc_handle* h, char* output, uint32_t capacity, uint32_t* required) {
    if (!h) return FC_INVALID_ARGUMENT;
    return copy(h->error, output, capacity, required);
}
int fc_research_hurt_tail(fc_handle* h, uint32_t slot, int32_t supplied) {
    return guarded(h, [&] { h->core.research_hurt_tail(fc::EntitySlot::checked(slot), supplied); return FC_OK; });
}
int fc_research_random_seed(fc_handle* h, int32_t seed) {
    return guarded(h, [&] { h->core.research_random_seed(seed); return FC_OK; });
}
int fc_research_random_int(fc_handle* h, int32_t low, int32_t high, int32_t* output) {
    return guarded(h, [&] {
        if (!output) return FC_INVALID_ARGUMENT;
        *output = h->core.research_random_int(low, high);
        return FC_OK;
    });
}
int fc_research_random_generation_count(fc_handle* h, uint64_t* output) {
    return guarded(h, [&] {
        if (!output) return FC_INVALID_ARGUMENT;
        *output = h->core.research_random_generation_count();
        return FC_OK;
    });
}
int fc_research_random_float(fc_handle* h, float low, float high, float* output) {
    return guarded(h, [&] {
        if (!output) return FC_INVALID_ARGUMENT;
        *output = h->core.research_random_float(low, high);
        return FC_OK;
    });
}
int fc_research_random_float_exp(fc_handle* h, float low, float high, float exponent, float* output) {
    return guarded(h, [&] {
        if (!output) return FC_INVALID_ARGUMENT;
        *output = h->core.research_random_float_exp(low, high, exponent);
        return FC_OK;
    });
}
int fc_research_hurt_profile_rng(fc_handle* h, uint32_t slot) {
    return guarded(h, [&] { h->core.research_hurt_profile_rng(fc::EntitySlot::checked(slot)); return FC_OK; });
}
int fc_research_feedback_tail(fc_handle* h, uint32_t slot, const fc_feedback_timing* timing) {
    return guarded(h, [&] {
        std::optional<fc::FeedbackTiming> input;
        if (timing) input = fc::FeedbackTiming{timing->stored_time, timing->counter_multiplier, timing->counter};
        h->core.research_feedback_tail(fc::RecordSlot::checked(slot), input);
        return FC_OK;
    });
}
int fc_research_get_state(fc_handle* h, uint32_t slot, uint32_t* reference, uint32_t* selected) {
    return guarded(h, [&] {
        if (!reference || !selected || reference == selected) return FC_INVALID_ARGUMENT;
        const auto result = h->core.research_state(fc::EntitySlot::checked(slot));
        *reference = result.first;
        *selected = result.second;
        return FC_OK;
    });
}
int fc_research_reset_arrays(fc_handle* h) {
    return guarded(h, [&] { h->core.research_reset_arrays(); return FC_OK; });
}
int fc_research_seed_record(fc_handle* h, uint32_t slot, uint64_t storage, uint32_t word0c,
                            uint32_t word10, const uint64_t* entries, uint32_t count) {
    return guarded(h, [&] {
        // Larger allocations need metadata that this small research ABI does not supply.
        if ((!entries && count) || count >= 1024) return FC_INVALID_ARGUMENT;
        fc::RecordSlice record;
        record.storage_token = storage;
        record.word_0c = word0c;
        record.word_10 = word10;
        record.count = count;
        if (count) record.entries.assign(entries, entries + count);
        h->core.research_seed_record(slot, std::move(record));
        return FC_OK;
    });
}
int fc_research_get_record(fc_handle* h, uint32_t slot, fc_record_snapshot* output) {
    return guarded(h, [&] {
        if (!output) return FC_INVALID_ARGUMENT;
        const auto record = h->core.research_record(slot);
        *output = {record.storage_token, record.count, record.word_0c, record.word_10, 0};
        return FC_OK;
    });
}
int fc_research_set_table_word(fc_handle* h, uint32_t slot, uint32_t value) {
    return guarded(h, [&] { h->core.research_set_table_word(slot, value); return FC_OK; });
}
int fc_research_get_table_word(fc_handle* h, uint32_t slot, uint32_t* output) {
    return guarded(h, [&] {
        if (!output) return FC_INVALID_ARGUMENT;
        *output = h->core.research_table_word(slot);
        return FC_OK;
    });
}
int fc_research_round_cleanup(fc_handle* h) {
    return guarded(h, [&] { h->core.research_round_cleanup(); return FC_OK; });
}
int fc_research_death_cleanup(fc_handle* h, uint64_t victim, uint64_t local, uint32_t first,
                              uint32_t second, uint32_t* result) {
    return guarded(h, [&] {
        if (!result) return FC_INVALID_ARGUMENT;
        *result = static_cast<uint32_t>(h->core.research_death_cleanup(victim, local, first, second));
        return FC_OK;
    });
}
int fc_research_record_trace(fc_handle* h, char* output, uint32_t capacity, uint32_t* required) {
    return guarded(h, [&] { return copy(h->core.research_record_trace(), output, capacity, required); });
}
}
