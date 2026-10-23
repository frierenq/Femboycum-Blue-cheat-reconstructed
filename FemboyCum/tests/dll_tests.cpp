#include "fc/api.h"
#include <bit>
#include <cmath>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
namespace {
unsigned checks{};
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
    ++checks;
}
using Read = int(*)(fc_handle*, char*, uint32_t, uint32_t*);
std::string read(Read function, fc_handle* handle) {
    uint32_t count{};
    require(function(handle, nullptr, 0, &count) == FC_OK && count, "size query");
    std::vector<char> buffer(count);
    require(function(handle, buffer.data(), count, &count) == FC_OK, "read result");
    require(buffer.back() == '\0', "NUL terminated result");
    return std::string(buffer.data(), count - 1);
}
struct Owned {
    fc_handle* value;
    explicit Owned(fc_handle* handle = fc_create()) : value(handle) {}
    ~Owned() { fc_destroy(value); }
    Owned(const Owned&) = delete;
    Owned& operator=(const Owned&) = delete;
};
}
int main() {
    try {
        require(fc_abi_version() == 1, "experimental ABI version");
        require(fc_shutdown(nullptr) == FC_INVALID_ARGUMENT, "null handle rejected");
        fc_destroy(nullptr);
        Owned handle;
        require(handle.value != nullptr, "allocate DLL-owned context");
        require(fc_set_text(handle.value, "x", 1) == FC_BAD_STATE, "inactive state reported");
        require(!read(fc_last_error, handle.value).empty(), "exception diagnostic retained");
        require(fc_initialize(handle.value, "bad", 3) == FC_INVALID_ARGUMENT, "malformed config reported");
        require(fc_initialize(handle.value, nullptr, 0) == FC_OK, "initialize default config");
        uint64_t rng_calls = 99;
        int32_t random_word = -1;
        require(fc_research_random_seed(handle.value, 1) == FC_OK &&
                fc_research_random_int(handle.value, 0, 2147483646, &random_word) == FC_OK && random_word == 893351816,
                "seeded default-stream projection through DLL");
        require(fc_research_random_int(handle.value, 1, 2, nullptr) == FC_INVALID_ARGUMENT &&
                fc_research_random_generation_count(handle.value, &rng_calls) == FC_OK && rng_calls == 1,
                "missing RNG output rejected before draw");
        require(fc_research_hurt_profile_rng(handle.value, 65) == FC_INVALID_ARGUMENT &&
                fc_research_random_generation_count(handle.value, &rng_calls) == FC_OK && rng_calls == 1,
                "unsupported hurt index rejected before draw");
        require(fc_research_hurt_profile_rng(handle.value, 0) == FC_OK &&
                fc_research_hurt_profile_rng(handle.value, 0) == FC_OK &&
                fc_research_random_generation_count(handle.value, &rng_calls) == FC_OK && rng_calls == 2,
                "hurt shares DLL RNG and nonzero transition consumes no draw");
        require(fc_research_random_int(handle.value, 0, 2147483646, &random_word) == FC_OK && random_word == 1624379149,
                "DLL integer API continues shared sequence after hurt");
        require(fc_research_random_generation_count(handle.value, nullptr) == FC_INVALID_ARGUMENT,
                "missing generation count output rejected");
        float random_float = -1.0f;
        require(fc_research_random_seed(handle.value, 2147483647) == FC_OK &&
                fc_research_random_float(handle.value, 10.0f, 20.0f, &random_float) == FC_OK &&
                std::bit_cast<uint32_t>(random_float) == 0x41200000u &&
                fc_research_random_generation_count(handle.value, &rng_calls) == FC_OK && rng_calls == 4,
                "float DLL call consumes maximum-seed zero draw and maps endpoints");
        require(fc_research_random_int(handle.value, 0, 2147483646, &random_word) == FC_OK && random_word == 893351816,
                "float and integer DLL calls share reinitialization state");
        require(fc_research_random_float(handle.value, 17.5f, 17.5f, &random_float) == FC_OK &&
                random_float == 17.5f &&
                fc_research_random_generation_count(handle.value, &rng_calls) == FC_OK && rng_calls == 6,
                "equal float endpoints consume one shared draw");
        require(fc_research_random_float(handle.value, 0.0f, 1.0f, nullptr) == FC_INVALID_ARGUMENT &&
                fc_research_random_generation_count(handle.value, &rng_calls) == FC_OK && rng_calls == 6,
                "missing float output rejected before draw");
        require(fc_research_random_seed(handle.value, 1) == FC_OK &&
                fc_research_random_float_exp(handle.value, 10.0f, 20.0f, 0.0f, &random_float) == FC_OK &&
                random_float == 20.0f &&
                fc_research_random_generation_count(handle.value, &rng_calls) == FC_OK && rng_calls == 7,
                "exponent zero consumes one shared DLL draw");
        require(fc_research_random_int(handle.value, 0, 2147483646, &random_word) == FC_OK &&
                random_word == 197493099,
                "integer DLL API continues exponent stream");
        require(fc_research_random_seed(handle.value, 2147483647) == FC_OK &&
                fc_research_random_float_exp(handle.value, 10.0f, 20.0f, 1.0f, &random_float) == FC_OK &&
                random_float == 10.0f,
                "ordered unit exponent skips helper for zero draw");
        require(fc_research_random_seed(handle.value, 2147483647) == FC_OK &&
                fc_research_random_float_exp(handle.value, 0.0f, 1.0f, -1.0f, &random_float) == FC_OK &&
                std::bit_cast<uint32_t>(random_float) == 0x7f800000u &&
                fc_research_random_generation_count(handle.value, &rng_calls) == FC_OK && rng_calls == 10,
                "exponent DLL helper handles zero factor and negative exponent");
        require(fc_research_random_float_exp(handle.value, 0.0f, 1.0f, 2.0f, nullptr) == FC_INVALID_ARGUMENT &&
                fc_research_random_generation_count(handle.value, &rng_calls) == FC_OK && rng_calls == 10,
                "missing exponent output rejected before draw");
        require(fc_research_random_int(handle.value, 0, 2147483646, &random_word) == FC_OK &&
                random_word == 893351816,
                "exponent zero output retains reinitialization for later DLL draws");
        require(fc_research_random_float_exp(handle.value, 0.0f, 1.0f,
                    std::bit_cast<float>(0x7fc00001u), &random_float) == FC_OK && std::isnan(random_float) &&
                fc_research_random_generation_count(handle.value, &rng_calls) == FC_OK && rng_calls == 12,
                "NaN exponent is classified through guarded DLL boundary");
        uint32_t reference{}, selected{};
        require(fc_research_get_state(handle.value, 64, &reference, &selected) == FC_OK && reference == 0 && selected == 0,
                "DLL owned state starts zero");
        require(fc_research_hurt_tail(handle.value, 64, 2) == FC_OK &&
                fc_research_get_state(handle.value, 64, &reference, &selected) == FC_OK && selected == 2,
                "hurt tail connected through DLL");
        require(fc_research_feedback_tail(handle.value, 63, nullptr) == FC_OK &&
                fc_research_get_state(handle.value, 64, &reference, &selected) == FC_OK && selected == 1,
                "record63 maps entity64 through DLL");
        const fc_feedback_timing timing{10.0f, 1.0f / 64.0f, 640};
        require(fc_research_feedback_tail(handle.value, 63, &timing) == FC_OK &&
                fc_research_get_state(handle.value, 64, &reference, &selected) == FC_OK && reference == 1 && selected == 1,
                "timing reference branch through DLL");
        require(fc_research_hurt_tail(handle.value, 65, 1) == FC_INVALID_ARGUMENT &&
                fc_research_feedback_tail(handle.value, 64, nullptr) == FC_INVALID_ARGUMENT,
                "unsupported owned indices rejected");
        require(fc_research_get_state(handle.value, 64, &reference, &reference) == FC_INVALID_ARGUMENT,
                "aliased output pointers rejected");
        require(fc_research_reset_arrays(handle.value) == FC_OK &&
                fc_research_get_state(handle.value, 64, &reference, &selected) == FC_OK && reference == 0 && selected == 0,
                "explicit array-reset block through DLL");
        const uint64_t resources[] = {11, 0, 22};
        fc_record_snapshot snapshot{};
        require(fc_research_seed_record(handle.value, 1, 100, 7, 9, resources, 3) == FC_OK,
                "seed token-only record through DLL");
        require(fc_research_set_table_word(handle.value, 4, 99) == FC_OK, "seed separate event table");
        uint32_t cleanup_result = 99;
        require(fc_research_death_cleanup(handle.value, 2, 1, 4, 1, &cleanup_result) == FC_OK && cleanup_result == 1,
                "nonlocal death uses two independently supplied indices");
        uint32_t table_value = 99;
        require(fc_research_get_table_word(handle.value, 4, &table_value) == FC_OK && table_value == 0,
                "first death index clears its table slot");
        require(fc_research_get_record(handle.value, 1, &snapshot) == FC_OK && snapshot.count == 0 &&
                snapshot.storage_token == 0 && snapshot.word_0c == 0 && snapshot.word_10 == 0 && snapshot.reserved == 0,
                "second death index releases its active record");
        const auto trace = read(fc_research_record_trace, handle.value);
        const auto release22 = trace.find("\"release_entry\",\"token\":22");
        const auto release11 = trace.find("\"release_entry\",\"token\":11");
        require(release22 != std::string::npos && release11 != std::string::npos && release22 < release11,
                "DLL trace preserves reverse entry release intent without freeing native pointers");
        require(fc_research_seed_record(handle.value, 2, 100, 7, 9, resources, 3) == FC_OK &&
                fc_research_set_table_word(handle.value, 4, 77) == FC_OK, "prepare partial unsupported death path");
        cleanup_result = 99;
        require(fc_research_death_cleanup(handle.value, 2, 1, 4, 65, &cleanup_result) == FC_UNSUPPORTED_ORIGINAL_PATH && cleanup_result == 99,
                "unsupported second-index path reported without invented result");
        require(fc_research_get_table_word(handle.value, 4, &table_value) == FC_OK && table_value == 0 &&
                fc_research_get_record(handle.value, 2, &snapshot) == FC_OK && snapshot.word_10 == 9,
                "unsupported path preserves first table effect and stops before record reset");
        require(fc_research_seed_record(handle.value, 3, 100, 7, 0, resources, 3) == FC_OK &&
                fc_research_hurt_tail(handle.value, 1, 2) == FC_OK, "prepare separate record and body-yaw banks");
        require(fc_research_round_cleanup(handle.value) == FC_OK &&
                fc_research_get_record(handle.value, 2, &snapshot) == FC_OK && snapshot.word_10 == 0 && snapshot.count == 0,
                "round cleanup resets eligible record slices");
        require(fc_research_get_record(handle.value, 3, &snapshot) == FC_OK && snapshot.storage_token == 100 && snapshot.count == 3,
                "round gate skips record with zero word10");
        require(fc_research_get_state(handle.value, 1, &reference, &selected) == FC_OK && selected == 2,
                "record cleanup does not invent a body-yaw array reset");
        require(read(fc_last_error, handle.value).empty(), "successful operation clears error");
        require(fc_initialize(handle.value, nullptr, 0) == FC_BAD_STATE, "double init reported");
        require(fc_set_text(handle.value, nullptr, 1) == FC_INVALID_ARGUMENT, "null input with size rejected");
        const std::string value("a\0b", 3);
        require(fc_set_text(handle.value, value.data(), 3) == FC_OK, "set embedded NUL text");
        require(read(fc_get_text, handle.value) == value, "length-based DLL string preserved");
        uint32_t required{};
        char sentinel = '!';
        require(fc_get_text(handle.value, &sentinel, 1, &required) == FC_BUFFER_TOO_SMALL && sentinel == '!' && required == 4,
                "short buffer remains untouched");
        require(fc_get_text(handle.value, nullptr, 1, &required) == FC_INVALID_ARGUMENT, "null output with capacity rejected");
        require(fc_get_text(handle.value, nullptr, 0, nullptr) == FC_INVALID_ARGUMENT, "missing size output rejected");
        require(fc_dispatch(handle.value, "mock.event", 10, 42) == FC_OK, "dispatch mock event through DLL");
        const auto saved = read(fc_save, handle.value);
        require(fc_shutdown(handle.value) == FC_OK, "shutdown through DLL");
        require(fc_initialize(handle.value, saved.data(), static_cast<uint32_t>(saved.size())) == FC_OK, "reload saved config");
        require(read(fc_get_text, handle.value) == value, "saved DLL text restored");
        require(fc_shutdown(handle.value) == FC_OK && fc_shutdown(handle.value) == FC_OK, "idempotent DLL shutdown");
        require(fc_lua_load_research_script(handle.value, "return 1", 8) == FC_BAD_STATE &&
                !read(fc_last_error, handle.value).empty(),
                "default mock handle rejects experimental Lua script with diagnostic");

        const auto lua_available = fc_lua_candidate_available();
        require(lua_available <= 1, "Lua candidate availability is boolean");
        Owned lua{fc_create_lua_candidate()};
        if (!lua_available) {
            require(lua.value == nullptr, "disabled Lua factory returns null");
        } else {
            require(lua.value != nullptr, "enabled Lua factory owns context");
            require(fc_lua_load_research_script(lua.value, "return 1", 8) == FC_BAD_STATE,
                    "Lua script load requires initialized core");
            require(fc_initialize(lua.value, nullptr, 0) == FC_OK, "initialize Lua-backed DLL context");
            const std::string script = R"lua(
                local ffi = require("ffi")
                assert(jit.arch == "x86" and ffi.sizeof("void *") == 4)
                ffi.cdef[[typedef struct { int x; int y; } FcDllPoint;]]
                local point = ffi.new("FcDllPoint", {17, 25})
                assert(point.x + point.y == 42)
                local callback = ffi.cast("int (__cdecl *)(int)", function(value) return value + 1 end)
                assert(callback(41) == 42)
                callback:free()
                lua_token = fc_research.on_event(function(name, tick)
                    if name == "lua.event" then
                        assert(fc_research.set_text("Lua DLL " .. tick))
                    end
                end)
            )lua";
            require(fc_lua_load_research_script(lua.value, script.data(), static_cast<uint32_t>(script.size())) == FC_OK,
                    "load real Lua/FFI callback through new research factory");
            require(fc_dispatch(lua.value, "lua.event", 9, 41) == FC_OK &&
                    read(fc_get_text, lua.value) == "Lua DLL 41",
                    "Lua callback edits core text through DLL");
            require(read(fc_save, lua.value).find("Lua DLL 41") != std::string::npos,
                    "Lua edit reaches serialized state");
            const std::string events_script = R"lua(
                event_function = function(value)
                    assert(fc_research.set_text("Event DLL " .. value))
                end
                events.dll_test:set(event_function)
                events.dll_test:set(event_function)
                assert(events.dll_test() == 1)
                event_bridge = fc_research.on_event(function(name, tick)
                    if name == "events.bridge" then events.dll_test:call(tick) end
                end)
            )lua";
            require(fc_lua_load_research_script(lua.value, events_script.data(),
                        static_cast<uint32_t>(events_script.size())) == FC_OK &&
                    fc_dispatch(lua.value, "events.bridge", 13, 77) == FC_OK &&
                    read(fc_get_text, lua.value) == "Event DLL 77",
                    "recovered Event candidate connects DLL script, dispatch and text edit");
            const std::string failed_event_chunk =
                "events.dll_test:set(function() end); error('Event chunk rollback')";
            require(fc_lua_load_research_script(lua.value, failed_event_chunk.data(),
                        static_cast<uint32_t>(failed_event_chunk.size())) == FC_INTERNAL_ERROR &&
                    read(fc_last_error, lua.value).find("Event chunk rollback") != std::string::npos,
                    "DLL boundary catches failed Event registration chunk");
            const std::string event_cleanup =
                "assert(events.dll_test() == 1); events.dll_test:unset(event_function); "
                "assert(events.dll_test() == 0); assert(fc_research.cancel(event_bridge))";
            require(fc_lua_load_research_script(lua.value, event_cleanup.data(),
                        static_cast<uint32_t>(event_cleanup.size())) == FC_OK,
                    "DLL failed-chunk rollback retains earlier Event registration only");
            const std::string writer_script = R"lua(
                dll_writer = fc_research.new_bit_writer20()
                dll_writer:write_bits(5, 3)
                dll_writer:crypt("\0A")
                assert(dll_writer:snapshot().data:byte(2) == 65)
                writer_bridge = fc_research.on_event(function(name)
                    if name == "writer.bridge" then
                        dll_writer:write_coord(-1.5)
                        local value = dll_writer:snapshot()
                        assert(not value.overflow)
                        local body = fc_research.voice_message_body(dll_writer)
                        assert(body:byte(1) == 0x11 and body:sub(2, 9) == value.data:sub(13, 20))
                        assert(body:byte(10) == 0x18 and body:byte(11) == 0)
                        local frame = fc_research.voice_message_frame(dll_writer)
                        assert(frame == string.char(10, #body) .. body and #frame <= 36)
                        assert(fc_research.set_text("Writer DLL " .. value.bit_cursor ..
                            ":" .. value.data:byte(1)))
                    elseif name == "writer.invalid" then
                        dll_writer:write_bits(1, 0)
                    end
                end)
            )lua";
            require(fc_lua_load_research_script(lua.value, writer_script.data(),
                        static_cast<uint32_t>(writer_script.size())) == FC_OK,
                    "DLL Lua factory owns a binary-key bit writer");
            require(fc_dispatch(lua.value, "writer.bridge", 13, 78) == FC_OK &&
                    read(fc_get_text, lua.value) == "Writer DLL 25:61",
                    "DLL callback writes coordinates and publishes owned snapshot");
            require(fc_dispatch(lua.value, "writer.invalid", 14, 79) == FC_INTERNAL_ERROR &&
                    read(fc_last_error, lua.value).find("1..32") != std::string::npos,
                    "invalid writer count stays inside protected DLL boundary");
            const std::string writer_cleanup =
                "assert(dll_writer:snapshot().bit_cursor == 25); "
                "assert(dll_writer:snapshot().data:byte(1) == 61); "
                "local body = fc_research.voice_message_body(dll_writer); "
                "assert(fc_research.voice_message_frame(dll_writer) == string.char(10, #body) .. body); "
                "assert(fc_research.cancel(writer_bridge))";
            require(fc_lua_load_research_script(lua.value, writer_cleanup.data(),
                        static_cast<uint32_t>(writer_cleanup.size())) == FC_OK,
                    "DLL writer survives rejected mutation and bridge cancellation");
            require(fc_lua_load_research_script(lua.value, "function (", 10) == FC_INTERNAL_ERROR &&
                    read(fc_last_error, lua.value).find("Lua compile error") != std::string::npos,
                    "Lua compile error returns guarded diagnostic");
            const std::string failing = "error('Lua load failure')";
            require(fc_lua_load_research_script(lua.value, failing.data(), static_cast<uint32_t>(failing.size())) ==
                    FC_INTERNAL_ERROR && read(fc_last_error, lua.value).find("Lua load failure") != std::string::npos,
                    "Lua runtime error returns guarded diagnostic");
            const std::string callback_error = R"lua(
                error_token = fc_research.on_event(function(name)
                    if name == "lua.error" then error("Lua callback failure") end
                end)
            )lua";
            require(fc_lua_load_research_script(lua.value, callback_error.data(),
                    static_cast<uint32_t>(callback_error.size())) == FC_OK,
                    "register second Lua callback");
            require(fc_dispatch(lua.value, "lua.error", 9, 42) == FC_INTERNAL_ERROR &&
                    read(fc_last_error, lua.value).find("Lua callback failure") != std::string::npos,
                    "Lua callback error stays inside protected DLL boundary");
            const std::string cancel = "assert(fc_research.cancel(lua_token)); assert(fc_research.cancel(error_token))";
            require(fc_lua_load_research_script(lua.value, cancel.data(), static_cast<uint32_t>(cancel.size())) == FC_OK,
                    "cancel Lua callbacks through research bridge");
            require(fc_set_text(lua.value, "sentinel", 8) == FC_OK &&
                    fc_dispatch(lua.value, "lua.event", 9, 43) == FC_OK &&
                    read(fc_get_text, lua.value) == "sentinel",
                    "cancelled Lua callback no longer edits text");
            const auto lua_saved = read(fc_save, lua.value);
            require(fc_shutdown(lua.value) == FC_OK, "Lua-backed DLL context shuts down");
            require(fc_initialize(lua.value, lua_saved.data(), static_cast<uint32_t>(lua_saved.size())) == FC_OK &&
                    read(fc_get_text, lua.value) == "sentinel",
                    "Lua-backed DLL context restarts from saved state");
            require(fc_dispatch(lua.value, "lua.event", 9, 44) == FC_OK &&
                    read(fc_get_text, lua.value) == "sentinel",
                    "old Lua callbacks do not survive restart");
            const std::string restart = R"lua(
                fc_research.on_event(function(name)
                    if name == "restart" then assert(fc_research.set_text("Lua restarted")) end
                end)
            )lua";
            require(fc_lua_load_research_script(lua.value, restart.data(), static_cast<uint32_t>(restart.size())) == FC_OK &&
                    fc_dispatch(lua.value, "restart", 7, 45) == FC_OK &&
                    read(fc_get_text, lua.value) == "Lua restarted",
                    "new Lua callback works after DLL restart");
            require(fc_shutdown(lua.value) == FC_OK, "restarted Lua-backed DLL context shuts down");
        }
        std::cout << "{\"passed\":true,\"checks\":" << checks << ",\"experimental_dll_loaded\":true,\"original_core_loaded\":false}\n";
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
