#pragma once
#include <stdint.h>
#if defined(_WIN32) && defined(FC_BUILD_DLL)
#define FC_API __declspec(dllexport)
#elif defined(_WIN32)
#define FC_API __declspec(dllimport)
#else
#define FC_API
#endif
#ifdef __cplusplus
extern "C" {
#endif
typedef struct fc_handle fc_handle;
enum fc_status { FC_OK = 0, FC_INVALID_ARGUMENT = 1, FC_BAD_STATE = 2,
                 FC_INTERNAL_ERROR = 3, FC_BUFFER_TOO_SMALL = 4,
                 FC_UNSUPPORTED_ORIGINAL_PATH = 5 };
FC_API uint32_t fc_abi_version(void);
FC_API fc_handle* fc_create(void);
/* Explicit experimental source-built LuaJIT path. No historical Lua API parity is claimed. */
FC_API uint32_t fc_lua_candidate_available(void);
FC_API fc_handle* fc_create_lua_candidate(void);
FC_API void fc_destroy(fc_handle* handle);
FC_API int fc_lua_load_research_script(fc_handle*, const char* source, uint32_t size);
FC_API int fc_initialize(fc_handle*, const char* config, uint32_t size);
FC_API int fc_shutdown(fc_handle*);
FC_API int fc_set_text(fc_handle*, const char* text, uint32_t size);
FC_API int fc_get_text(fc_handle*, char* output, uint32_t capacity, uint32_t* required);
FC_API int fc_dispatch(fc_handle*, const char* name, uint32_t size, uint64_t tick);
FC_API int fc_save(fc_handle*, char* output, uint32_t capacity, uint32_t* required);
FC_API int fc_last_error(fc_handle*, char* output, uint32_t capacity, uint32_t* required);
/* Explicit local-tail replay. Native event eligibility is NOT supplied by this ABI. */
typedef struct fc_feedback_timing {
    float stored_time;
    float counter_multiplier;
    int32_t counter;
} fc_feedback_timing;
FC_API int fc_research_hurt_tail(fc_handle*, uint32_t second_entity_index, int32_t supplied_rng_word);
/* Explicit owned default-stream projection; does not select or replace a live engine stream. */
FC_API int fc_research_random_seed(fc_handle*, int32_t seed);
FC_API int fc_research_random_int(fc_handle*, int32_t low, int32_t high, int32_t* output);
FC_API int fc_research_random_float(fc_handle*, float low, float high, float* output);
FC_API int fc_research_random_float_exp(fc_handle*, float low, float high, float exponent, float* output);
FC_API int fc_research_random_generation_count(fc_handle*, uint64_t* output);
FC_API int fc_research_hurt_profile_rng(fc_handle*, uint32_t second_entity_index);
FC_API int fc_research_feedback_tail(fc_handle*, uint32_t reloaded_record_index, const fc_feedback_timing*);
FC_API int fc_research_get_state(fc_handle*, uint32_t entity_index, uint32_t* reference, uint32_t* selected);
FC_API int fc_research_reset_arrays(fc_handle*);
typedef struct fc_record_snapshot {
    uint64_t storage_token;
    uint32_t count;
    uint32_t word_0c;
    uint32_t word_10;
    uint32_t reserved;
} fc_record_snapshot;
/* Resource values are opaque tokens. Replay records release intents, never frees pointers. */
FC_API int fc_research_seed_record(fc_handle*, uint32_t slot, uint64_t storage_token,
                                  uint32_t word_0c, uint32_t word_10,
                                  const uint64_t* entry_tokens, uint32_t count);
FC_API int fc_research_get_record(fc_handle*, uint32_t slot, fc_record_snapshot*);
FC_API int fc_research_set_table_word(fc_handle*, uint32_t slot, uint32_t value);
FC_API int fc_research_get_table_word(fc_handle*, uint32_t slot, uint32_t* value);
FC_API int fc_research_round_cleanup(fc_handle*);
FC_API int fc_research_death_cleanup(fc_handle*, uint64_t victim_token, uint64_t reloaded_local_token,
                                    uint32_t first_index, uint32_t second_index, uint32_t* result);
FC_API int fc_research_record_trace(fc_handle*, char* output, uint32_t capacity, uint32_t* required);
#ifdef __cplusplus
}
#endif
