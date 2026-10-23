#include "fc/lua_host.hpp"
#include "fc/mock.hpp"
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
unsigned checks{};
void check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
    ++checks;
}
}

int main() {
    try {
        fc::MockEngine engine;
        fc::LuaJitCandidateHost host;
        fc::RecordingRenderer renderer;
        fc::Core core(engine, host, renderer);
        host.bind(core);
        core.initialize();
        host.load_research_script(R"lua(
            local name = string.rep("owned Event name ", 32)
            local event = events[name]
            assert(type(event) == "userdata" and event ~= events[name])
            assert(getmetatable(event) == getmetatable(events[name]))
            local calls = 0
            local callback = function(...)
                calls = calls + 1
                assert(select('#', ...) == 4)
                local a,b,c,d = ...
                assert(a == 17 and b == nil and c == "x\0y" and d == false)
                return "ignored", 42
            end
            name = nil
            collectgarbage()
            assert(event() == 0)
            event:set(callback)
            event:set(callback)
            assert(event() == 1)
            event:call(17, nil, "x\0y", false)
            assert(calls == 1)
            event(callback)
            assert(event() == 0)
            event(callback)
            assert(event() == 1)
            event(callback, false)
            event(callback, false)
            assert(event() == 0)
            event(callback, true)
            event(callback, true)
            assert(event() == 1)
            event:unset(callback)
            event:unset(callback)
            assert(event() == 0)

            local collide = function() end
            events.Aa:set(collide)
            assert(events["B@"]() == 1)
            events["B@"]:unset(collide)
            assert(events.Aa() == 0)
            local signed = events[string.char(255,65)]
            signed:set(collide)
            assert(events[string.char(0,32)]() == 1)
            events[string.char(0,32)]:unset(collide)
            assert(signed() == 0)
            events["a\0b"]:set(collide)
            assert(events.a() == 0)
            events["a\0b"]:unset(collide)
            assert(not pcall(function() return events[7] end))
            assert(not pcall(function() event:set(7) end))
            assert(not pcall(function() event(callback, 1) end))
            assert(event() == 0)
        )lua");
        check(true, "Event names, payloads, overloads, deduplication and signed length hash");

        host.load_research_script(R"lua(
            local function name_for_hash(hash)
                local remainder = (hash - (5381 * 33^7) % 4294967296) % 4294967296
                local bytes = {}
                for i = 7,1,-1 do
                    bytes[i] = string.char(remainder % 33)
                    remainder = math.floor(remainder / 33)
                end
                assert(remainder == 0)
                return table.concat(bytes)
            end
            local guards = {0x987aff41,0x9c62a07f,0xb1db03ab,0xd3793758,
                0xd7e8e984,0xdc09e123,0xfc460361,0x03b7c8c4,0x087391ca,
                0x16422f92,0x192ccfe5,0x1a0e622e,0x1bf01450,0x2b687d4a,
                0x2ecdb4b7,0x3647f691,0x76c9fe3b}
            for _,hash in ipairs(guards) do
                local event = events[name_for_hash(hash)]
                local ran = false
                local callback = function() ran = true end
                event:set(callback)
                assert(event() == 1)
                event:call()
                assert(not ran)
                event:unset(callback)
            end
            local special = events[name_for_hash(0xdb78e17f)]
            local ran = false
            local callback = function() ran = true end
            special:set(callback)
            local ok,err = pcall(function() special:call() end)
            assert(not ok and tostring(err):find("not reconstructed",1,true) and not ran)
            special:unset(callback)
        )lua");
        check(true, "all17 native skip hashes and separate unsupported special route");

        host.load_research_script(R"lua(
            local event = events["candidate.mutation"]
            local trace = ""
            local first = true
            local late = function() trace = trace .. "d" end
            local cancelled = function() trace = trace .. "b" end
            event:set(function()
                trace = trace .. "a"
                if first then
                    first = false
                    event:unset(cancelled)
                    event:set(late)
                end
            end)
            event:set(cancelled)
            event:set(function() trace = trace .. "c" end)
            event:call()
            assert(trace == "ac")
            event:call()
            assert(trace == "acacd")
            local errors = events["candidate.error"]
            local tail = false
            local bad = function() error("candidate event failure") end
            errors:set(bad)
            errors:set(function() tail = true end)
            local ok,err = pcall(function() errors:call() end)
            assert(not ok and tostring(err):find("candidate event failure",1,true) and not tail)
            errors:unset(bad)
            errors:call()
            assert(tail)
            local coroutine_event = events["candidate.coroutine"]
            local invoked = 0
            local callback = function() invoked = invoked + 1 end
            local thread = coroutine.create(function()
                coroutine_event:set(callback)
                coroutine_event:call()
                coroutine_event:unset(callback)
            end)
            assert(coroutine.resume(thread) and invoked == 1 and coroutine_event() == 0)
        )lua");
        check(true, "stable mutation, protected errors and one-state coroutine use");

        host.load_research_script(R"lua(
            weak_events = setmetatable({}, {__mode="v"})
            weak_callbacks = setmetatable({}, {__mode="v"})
            do
                local event = events["candidate.gc"]
                local callback = function() end
                weak_events[1] = event
                weak_callbacks[1] = callback
                event:set(callback)
            end
        )lua");
        host.load_research_script(R"lua(
            collectgarbage()
            assert(weak_events[1] == nil and weak_callbacks[1] ~= nil)
            events["candidate.gc"]:unset(weak_callbacks[1])
        )lua");
        host.load_research_script("collectgarbage(); assert(weak_callbacks[1] == nil)");
        check(true, "userdata GC and callback retention/release");

        host.load_research_script(R"lua(
            events["candidate.engine_bridge"]:set(function(name,tick)
                assert(name == "authored.engine.event" and tick == 42)
                assert(fc_research.set_text("Event candidate connected"))
            end)
            fc_research.on_event(function(name,tick)
                events["candidate.engine_bridge"]:call(name,tick)
            end)
        )lua");
        core.dispatch({"authored.engine.event", 42});
        check(core.text() == "Event candidate connected" &&
              core.save().find("Event candidate connected") != std::string::npos,
              "new engine bridge explicitly routes manual Event payload to text/save");
        core.shutdown();
        core.initialize();
        host.load_research_script("assert(events['candidate.engine_bridge']() == 0)");
        check(true, "restart creates fresh candidate registry");
        host.load_research_script(R"lua(
            retained_calls, cancelled_calls, failed_calls = 0,0,0
            retained = function() retained_calls = retained_calls + 1 end
            cancelled = function() cancelled_calls = cancelled_calls + 1 end
            events["candidate.rollback"]:set(retained)
            events["candidate.rollback"]:set(cancelled)
        )lua");
        bool failed_chunk = false;
        try {
            host.load_research_script(R"lua(
                events["candidate.rollback"]:unset(cancelled)
                local added = function() failed_calls = failed_calls + 1 end
                failed_weak = setmetatable({added}, {__mode="v"})
                events["candidate.rollback"]:set(added)
                assert(fc_research.set_text("successful earlier edit"))
                error("rollback new Event registrations")
            )lua");
        } catch (const std::runtime_error&) { failed_chunk = true; }
        check(failed_chunk && core.text() == "successful earlier edit", "failed chunk preserves earlier core edit");
        host.load_research_script(R"lua(
            collectgarbage()
            assert(events["candidate.rollback"]() == 1 and failed_weak[1] == nil)
            events["candidate.rollback"]:call()
            assert(retained_calls == 1 and cancelled_calls == 0 and failed_calls == 0)
        )lua");
        check(true, "failed chunk removes only new registrations and preserves cancellation");

        unsigned allocation_failures = 0;
        unsigned event_failure_stages = 0;
        for (std::size_t budget = 0; budget <= 40; ++budget) {
            fc::MockEngine fault_engine;
            fc::LuaJitCandidateHost fault_host;
            fc::RecordingRenderer fault_renderer;
            fc::Core fault_core(fault_engine, fault_host, fault_renderer);
            fault_host.bind(fault_core);
            fault_core.initialize();
            fault_host.load_research_script(R"lua(
                oom_stage = 0
                oom_name = string.rep("candidate allocation name ", 32)
                oom_callback = function() end
                fc_research.on_event(function()
                    oom_stage = 1
                    local event = events[oom_name]
                    oom_stage = 2
                    event:set(oom_callback)
                    oom_stage = 3
                    event:call()
                    oom_stage = 4
                    event:unset(oom_callback)
                end)
            )lua");
            fault_host.fail_next_allocation_for_test(budget);
            bool failed = false;
            try { fault_core.dispatch({"candidate.oom", 1}); }
            catch (const std::runtime_error&) { failed = true; ++allocation_failures; }
            fault_host.fail_next_allocation_for_test(static_cast<std::size_t>(-1));
            fault_host.load_research_script("assert(fc_research.set_text(tostring(oom_stage)))");
            if (failed) event_failure_stages |= 1u << static_cast<unsigned>(std::stoul(fault_core.text()));
            fault_core.dispatch({"candidate.oom", 2});
            fault_host.load_research_script("assert(oom_stage == 4 and events[oom_name]() == 0)");
            check(fault_core.active(), "Event allocation failure preserves usable state");
        }
        check(allocation_failures != 0 && (event_failure_stages & 0x0eu) == 0x0eu,
              "allocation faults reach Event lookup, registration and snapshot dispatch");
        std::cout << "{\"passed\":true,\"checks\":" << checks
                  << ",\"allocation_failures\":" << allocation_failures
                  << ",\"allocation_failure_stage_mask\":" << event_failure_stages
                  << ",\"lua_event_candidate_executed\":true,\"native_reference_comparison\":false}\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
