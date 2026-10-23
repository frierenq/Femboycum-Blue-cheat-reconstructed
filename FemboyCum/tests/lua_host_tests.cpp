#include "fc/lua_host.hpp"
#include "fc/mock.hpp"

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
unsigned checks{};

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
    ++checks;
}

template<class Function> void rejects(Function function, const char* message) {
    bool rejected = false;
    try { function(); } catch (const std::exception&) { rejected = true; }
    require(rejected, message);
}
} // namespace

int main() {
    try {
        fc::MockEngine engine;
        fc::LuaJitCandidateHost scripts;
        fc::RecordingRenderer renderer;
        fc::Core core(engine, scripts, renderer);
        scripts.bind(core);

        core.initialize();
        scripts.load_research_script(R"lua(
            local ffi = require("ffi")
            assert(jit.version == "LuaJIT 2.1.0-beta3")
            assert(jit.arch == "x86" and jit.os == "Windows")
            assert(ffi.sizeof("void *") == 4)
            ffi.cdef[[
                typedef struct { int x; int y; } FcPoint;
                unsigned long __stdcall GetCurrentProcessId(void);
            ]]
            local point = ffi.new("FcPoint", {17, 25})
            assert(point.x + point.y == 42 and ffi.sizeof(point) == 8)
            local wide = ffi.new("uint64_t", 4294967297)
            assert(tonumber(wide) == 4294967297)
            assert(ffi.typeof("int (__thiscall *)(void *, int)"))
            local kernel32 = ffi.load("kernel32")
            assert(tonumber(kernel32.GetCurrentProcessId()) > 0)
            local callback = ffi.cast("int (__cdecl *)(int)", function(value)
                return value + 1
            end)
            assert(callback(41) == 42)
            callback:free()
            first = fc_research.on_event(function(name, tick)
                if name == "mock.event" then
                    assert(fc_research.set_text("Lua tick " .. tick))
                end
            end)
            assert(type(first) == "number")
        )lua");
        require(scripts.callback_count() == 1, "real Lua callback registered");
        core.dispatch({"mock.event", 7});
        require(core.text() == "Lua tick 7", "Lua callback wrote core text");
        core.render();
        require(renderer.frames.back().second == "Lua tick 7", "renderer saw Lua text");
        require(fc::ConfigDocument::parse(core.save()).fields.at("setting.text") == "Lua tick 7",
                "saved config captured Lua edit");

        rejects([&] { scripts.load_research_script("function ("); }, "compile error protected");
        rejects([&] {
            scripts.load_research_script("fc_research.on_event(function() end); error('failed chunk')");
        }, "script error protected");
        require(scripts.callback_count() == 1, "failed script releases its new callbacks");
        scripts.load_research_script(R"lua(
            local token, message = fc_research.on_event(3)
            assert(token == nil and type(message) == "string")
            local cancelled, reason = fc_research.cancel(-1)
            assert(cancelled == nil and type(reason) == "string")
            bad = fc_research.on_event(function(name, tick)
                if name == "error" then error("raised from Lua") end
                if name == "boundary" then assert(tick == 9007199254740991) end
            end)
        )lua");
        rejects([&] { core.dispatch({"error", 8}); }, "event error protected");
        rejects([&] { core.dispatch({"mock.event", std::uint64_t{1} << 53}); },
                "inexact Lua event tick rejected");
        core.dispatch({"boundary", (std::uint64_t{1} << 53) - 1});
        require(core.text() == "Lua tick 7", "largest exact Lua event tick accepted");
        core.dispatch({"mock.event", 9});
        require(core.text() == "Lua tick 9", "stack restored after callback error");
        scripts.load_research_script("assert(fc_research.cancel(bad)); assert(not fc_research.cancel(bad))");
        require(scripts.callback_count() == 1, "cancellation releases Lua callback");

        scripts.load_research_script(R"lua(
            local installed = false
            local victim
            fc_research.on_event(function(name)
                if name == "order" then
                    fc_research.cancel(victim)
                    assert(fc_research.set_text("first"))
                    if not installed then
                        installed = true
                        fc_research.on_event(function(next_name)
                            if next_name == "order" then
                                assert(fc_research.set_text("third"))
                            end
                        end)
                    end
                end
            end)
            victim = fc_research.on_event(function(name)
                if name == "order" then assert(fc_research.set_text("victim")) end
            end)
        )lua");
        core.dispatch({"order", 10});
        require(core.text() == "first", "cancelled callback skipped and new callback deferred");
        core.dispatch({"order", 11});
        require(core.text() == "third", "new callback runs on next event");
        require(scripts.callback_count() == 3, "callback ownership after mutation");

        scripts.load_research_script(R"lua(
            local old = fc_research.on_event(function(name)
                if name == "failed-mutation" then assert(fc_research.set_text("old ran")) end
            end)
            local changed = false
            fc_research.on_event(function(name)
                if name == "failed-mutation" and not changed then
                    changed = true
                    assert(fc_research.cancel(old))
                    fc_research.on_event(function(next_name)
                        if next_name == "failed-mutation" then
                            assert(fc_research.set_text("new ran"))
                        end
                    end)
                    error("callback failed after mutation")
                end
            end)
        )lua");
        rejects([&] { core.dispatch({"failed-mutation", 12}); },
                "callback failure after registration and cancellation is protected");
        require(core.text() == "old ran", "failing event keeps earlier callback effects");
        core.dispatch({"failed-mutation", 13});
        require(core.text() == "new ran", "callback mutation survives a failed event");
        require(scripts.callback_count() == 5,
                "failed event cancellation and replacement preserve callback ownership");

        scripts.load_research_script(R"lua(
            local ok, message = fc_research.set_text(string.rep("x", 1048576))
            assert(ok == nil and type(message) == "string")
        )lua");
        require(core.text() == "new ran", "C++ set_text failure returned into Lua without unwinding across C");

        core.shutdown();
        require(!core.active() && scripts.callback_count() == 0 && engine.resets == 1,
                "shutdown releases Lua state and callbacks");
        rejects([&] { scripts.load_research_script("return 1"); }, "inactive Lua host rejects execution");

        core.initialize();
        core.dispatch({"mock.event", 12});
        require(core.text() == "Source-owned research", "old Lua callbacks do not return after restart");
        scripts.load_research_script(R"lua(
            fc_research.on_event(function(name)
                if name == "restart" then assert(fc_research.set_text("restarted")) end
            end)
        )lua");
        core.dispatch({"restart", 13});
        require(fc::ConfigDocument::parse(core.save()).fields.at("setting.text") == "restarted",
                "restarted Lua callback saved text");
        core.shutdown();
        require(scripts.callback_count() == 0 && engine.resets == 2,
                "second shutdown releases callbacks");

        fc::MockEngine fault_engine;
        fc::LuaJitCandidateHost fault_scripts;
        fc::RecordingRenderer fault_renderer;
        fc::Core fault_core(fault_engine, fault_scripts, fault_renderer);
        fault_scripts.bind(fault_core);
        fault_scripts.fail_next_allocation_for_test();
        rejects([&] { fault_core.initialize(); }, "Lua initialization allocation failure protected");
        require(!fault_core.active() && fault_scripts.callback_count() == 0,
                "failed Lua initialization cleans up state");
        fault_core.initialize();
        fault_scripts.load_research_script(R"lua(
            fc_research.on_event(function(name)
                if name == "recovered" then assert(fc_research.set_text("allocator recovered")) end
            end)
        )lua");
        fault_scripts.fail_next_allocation_for_test(1);
        rejects([&] { fault_core.dispatch({std::string(4096, 'q'), 1}); },
                "Lua event argument allocation failure protected");
        require(fault_scripts.last_event_stage_for_test() == 2,
                "allocation failure reached protected event-name push");
        fault_core.dispatch({"recovered", 2});
        require(fault_core.text() == "allocator recovered", "Lua event stack usable after allocation failure");
        fault_core.shutdown();
        fault_core.initialize();
        fault_core.shutdown();
        require(!fault_core.active() && fault_scripts.callback_count() == 0,
                "allocation fault lifecycle can restart and stop");

        unsigned cleanup_failure_cases = 0;
        unsigned callback_cleanup_failures = 0;
        unsigned event_cleanup_failures = 0;
        for (std::size_t budget = 0; budget <= 96; ++budget) {
            fc::MockEngine cleanup_engine;
            fc::LuaJitCandidateHost cleanup_scripts;
            fc::RecordingRenderer cleanup_renderer;
            fc::Core cleanup_core(cleanup_engine, cleanup_scripts, cleanup_renderer);
            cleanup_scripts.bind(cleanup_core);
            cleanup_core.initialize();
            cleanup_scripts.load_research_script(R"lua(
                events["candidate.cleanup"]:set(function() end)
                fc_research.on_event(function() end)
            )lua");
            cleanup_scripts.fail_allocations_for_test(budget);
            std::string failure;
            try {
                cleanup_scripts.load_research_script(R"lua(
                    events["candidate.cleanup"]:set(function() end)
                    fc_research.on_event(function() end)
                    error("deliberate failed chunk")
                )lua");
            } catch (const std::exception& error) { failure = error.what(); }
            require(!failure.empty(), "persistent fault or deliberate failed chunk is protected");
            if (failure.find("cleanup failed") != std::string::npos) {
                ++cleanup_failure_cases;
                if (failure == "Lua callback cleanup failed") ++callback_cleanup_failures;
                if (failure == "Lua candidate Event cleanup failed") ++event_cleanup_failures;
                require(!cleanup_core.active() && cleanup_scripts.callback_count() == 0,
                        "cleanup failure shuts down the core and clears callback ownership");
                rejects([&] { cleanup_scripts.load_research_script("return 1"); },
                        "closed host rejects loads after cleanup failure");
                rejects([&] { cleanup_core.dispatch({"candidate.cleanup", 1}); },
                        "closed core rejects events after cleanup failure");
                cleanup_core.initialize();
                cleanup_scripts.load_research_script(
                    "assert(events['candidate.cleanup']() == 0)");
                require(cleanup_scripts.callback_count() == 0,
                        "reinitialized host contains no prior fc_research callbacks");
            } else {
                cleanup_scripts.fail_next_allocation_for_test(static_cast<std::size_t>(-1));
            }
            cleanup_core.shutdown();
        }
        require(callback_cleanup_failures != 0 && event_cleanup_failures != 0,
                "persistent allocation sweep reached both protected cleanup failure paths");

        std::cout << "{\"passed\":true,\"checks\":" << checks
                  << ",\"cleanup_failure_cases\":" << cleanup_failure_cases
                  << ",\"callback_cleanup_failures\":" << callback_cleanup_failures
                  << ",\"event_cleanup_failures\":" << event_cleanup_failures
                  << ",\"lua_executed\":true,\"ffi_executed\":true,"
                     "\"reference_comparison\":false}\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
