#include "fc/lua_host.hpp"
#include "fc/mock.hpp"

#include <iostream>
#include <limits>
#include <stdexcept>

namespace {
unsigned checks{};
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
    ++checks;
}
template<class Function> void rejects(Function&& function, const char* message) {
    bool rejected = false;
    try { function(); } catch (const std::exception&) { rejected = true; }
    require(rejected, message);
}
}

int main() {
    try {
        fc::MockEngine engine;
        fc::LuaJitCandidateHost scripts;
        fc::RecordingRenderer renderer;
        fc::Core core(engine, scripts, renderer);
        scripts.bind(core);
        core.initialize();

        scripts.load_research_script(R"lua(
            assert(type(fc_research.new_bit_writer20) == "function")
            assert(type(fc_research.voice_message_body) == "function")
            assert(type(fc_research.voice_message_frame) == "function")
            local w = fc_research.new_bit_writer20()
            assert(type(w) == "userdata")
            local first = w:snapshot()
            assert(#first.data == 20 and first.data == string.rep("\0", 20))
            assert(first.bit_cursor == 0 and not first.overflow and not w:is_overflowed())
            local zero_body = fc_research.voice_message_body(w)
            assert(zero_body == string.char(0x11) .. string.rep("\0", 8) ..
                   string.char(0x18, 0, 0x20, 0, 0x28, 0, 0x30, 0))
            assert(#zero_body == 17)
            assert(fc_research.voice_message_frame(w) == string.char(10, #zero_body) .. zero_body)
            assert(not pcall(function() fc_research.voice_message_body(3) end))
            assert(not pcall(function() fc_research.voice_message_body(w, 1) end))
            assert(not pcall(function() fc_research.voice_message_frame(3) end))
            assert(not pcall(function() fc_research.voice_message_frame(w, 1) end))
            w:write_bits(5, 3)
            w:write_bits(3, 2)
            local bits = w:snapshot()
            assert(bits.bit_cursor == 5 and bits.data:byte(1) == 29)
            assert(not bits.overflow)
            local function unchanged_after_reject(action)
                local before = w:snapshot()
                assert(not pcall(action))
                local after = w:snapshot()
                assert(after.data == before.data and
                       after.bit_cursor == before.bit_cursor and
                       after.overflow == before.overflow)
            end
            unchanged_after_reject(function() w:write_bits(1, 0) end)
            unchanged_after_reject(function() w:write_bits(1, 33) end)
            unchanged_after_reject(function() w:write_bits(1, -1) end)
            unchanged_after_reject(function() w:write_bits(1, 1.5) end)
            unchanged_after_reject(function() w:write_bits(8, 3) end)
            unchanged_after_reject(function() w:write_bits(-1, 32) end)
            unchanged_after_reject(function() w:write_bits(4294967296, 32) end)
            unchanged_after_reject(function() w:write_bits(1, "1") end)
            unchanged_after_reject(function() w:write_coord(math.huge) end)
            unchanged_after_reject(function() w:write_coord(0/0) end)
            unchanged_after_reject(function() w:write_coord(16385) end)
            unchanged_after_reject(function() w:write_coord(1e300) end)
            unchanged_after_reject(function() w:write_coord(-1e300) end)
            unchanged_after_reject(function() w:write_coord("1") end)
            unchanged_after_reject(function() w:crypt(3) end)
            assert(not pcall(function() fc_research.new_bit_writer20(1) end))

            local c = fc_research.new_bit_writer20()
            c:crypt("\0A")
            local encrypted = c:snapshot()
            assert(encrypted.bit_cursor == 0 and not encrypted.overflow)
            for index = 1, 20 do
                assert(encrypted.data:byte(index) == (index % 2 == 1 and 0 or 65))
            end
            c:crypt("\0A")
            assert(c:snapshot().data == string.rep("\0", 20))
            c:crypt("")
            assert(c:snapshot().data == string.rep("\0", 20))

            local full = fc_research.new_bit_writer20()
            for _ = 1, 5 do full:write_bits(0xffffffff, 32) end
            assert(full:snapshot().bit_cursor == 160)
            local full_data = full:snapshot().data
            full:write_bits(1, 1)
            assert(full:snapshot().bit_cursor == 160 and not full:is_overflowed())
            assert(full:snapshot().data == full_data)
            local full_body = fc_research.voice_message_body(full)
            assert(#full_body == 34)
            assert(full_body == string.char(0x11) .. string.rep(string.char(0xff), 8) ..
                   string.char(0x18, 0, 0x20) .. string.rep(string.char(0xff), 9) ..
                   string.char(1, 0x28, 0xff, 0xff, 0xff, 0xff, 0x0f,
                               0x30, 0xff, 0xff, 0xff, 0xff, 0x0f))
            local full_frame = fc_research.voice_message_frame(full)
            assert(#full_frame == 36 and full_frame == string.char(10, #full_body) .. full_body)
            full:write_coord(1)
            assert(full:is_overflowed() and full:snapshot().data == full_data)
            assert(not pcall(function() fc_research.voice_message_body(full) end))
            assert(not pcall(function() fc_research.voice_message_frame(full) end))

            local partial = fc_research.new_bit_writer20()
            for _ = 1, 4 do partial:write_bits(0, 32) end
            partial:write_bits(0, 31)
            partial:write_coord(1)
            local part = partial:snapshot()
            assert(part.bit_cursor == 160 and part.overflow)
            assert(part.data:byte(20) == 128)

            local finalized = fc_research.new_bit_writer20()
            local mt = debug.getmetatable(finalized)
            local forged = newproxy(true)
            debug.setmetatable(forged, mt)
            assert(not pcall(function() forged:snapshot() end))
            assert(not pcall(function() fc_research.voice_message_frame(forged) end))
            mt.__gc(finalized)
            assert(not pcall(function() finalized:snapshot() end))
            assert(not pcall(function() fc_research.voice_message_frame(finalized) end))
            mt.__gc(finalized)
            do
                local weak = setmetatable({}, {__mode = "v"})
                weak.writer = fc_research.new_bit_writer20()
                collectgarbage("collect")
                collectgarbage("collect")
                assert(weak.writer == nil)
            end
        )lua");
        require(core.active(), "candidate factory and protected Lua assertions remain active");

        scripts.load_research_script(R"lua(
            held_writer = fc_research.new_bit_writer20()
            fc_research.on_event(function(name)
                if name == "writer.step" then held_writer:write_bits(1, 1) end
                if name == "writer.bad" then held_writer:write_bits(1, 0) end
            end)
        )lua");
        core.dispatch({"writer.step", 1});
        core.dispatch({"writer.step", 2});
        rejects([&] { core.dispatch({"writer.bad", 3}); },
                "invalid callback write propagates through protected host");
        scripts.load_research_script(R"lua(
            local s = held_writer:snapshot()
            assert(s.bit_cursor == 2 and s.data:byte(1) == 3 and not s.overflow)
        )lua");
        core.dispatch({"writer.step", 4});
        scripts.load_research_script("assert(held_writer:snapshot().bit_cursor == 3)");
        require(core.active(), "host usable after rejected callback write");

        scripts.load_research_script(R"lua(
            allocation_stage = -1
            fc_research.on_event(function(name)
                if name == "writer.alloc" then
                    allocation_stage = 0
                    local writer = fc_research.new_bit_writer20()
                    allocation_stage = 1
                    local state = writer:snapshot()
                    assert(#state.data == 20)
                    allocation_stage = 2
                end
            end)
        )lua");
        bool saw_factory_allocation_failure = false;
        bool saw_snapshot_allocation_failure = false;
        std::size_t factory_fault_budget = std::numeric_limits<std::size_t>::max();
        std::size_t snapshot_fault_budget = std::numeric_limits<std::size_t>::max();
        for (std::size_t budget = 0;
             budget < 96 && !(saw_factory_allocation_failure && saw_snapshot_allocation_failure);
             ++budget) {
            scripts.load_research_script("allocation_stage = -1");
            scripts.fail_next_allocation_for_test(budget);
            bool failed = false;
            try { core.dispatch({"writer.alloc", 100 + budget}); }
            catch (const std::exception&) { failed = true; }
            scripts.fail_next_allocation_for_test(std::numeric_limits<std::size_t>::max());
            require(core.active(), "one-shot Lua allocation failure keeps host coherent");
            scripts.load_research_script("assert(fc_research.set_text(tostring(allocation_stage)))");
            if (failed && core.text() == "0") {
                saw_factory_allocation_failure = true;
                factory_fault_budget = budget;
            }
            if (failed && core.text() == "1") {
                saw_snapshot_allocation_failure = true;
                snapshot_fault_budget = budget;
            }
            scripts.load_research_script(R"lua(
                local probe = fc_research.new_bit_writer20()
                assert(#probe:snapshot().data == 20)
            )lua");
        }
        require(saw_factory_allocation_failure,
                "one-shot fault reached owned writer creation after callback entry");
        require(saw_snapshot_allocation_failure,
                "one-shot fault reached writer snapshot after creation");

        scripts.load_research_script(R"lua(
            voice_allocation_stage = -1
            voice_allocation_counter = 0
            voice_allocation_writer = fc_research.new_bit_writer20()
            fc_research.on_event(function(name)
                if name == "writer.voice_alloc" or name == "writer.voice_frame_alloc" then
                    voice_allocation_stage = 0
                    voice_allocation_counter = voice_allocation_counter + 1
                    voice_allocation_writer:crypt(string.char(voice_allocation_counter))
                    voice_allocation_stage = 1
                    local output
                    if name == "writer.voice_alloc" then
                        output = fc_research.voice_message_body(voice_allocation_writer)
                    else
                        output = fc_research.voice_message_frame(voice_allocation_writer)
                    end
                    voice_allocation_stage = 2
                    voice_last_output = output
                end
            end)
        )lua");
        bool saw_body_allocation_failure = false;
        bool saw_frame_allocation_failure = false;
        std::size_t body_fault_budget = std::numeric_limits<std::size_t>::max();
        std::size_t frame_fault_budget = std::numeric_limits<std::size_t>::max();
        for (int kind = 0; kind != 2; ++kind) {
            const bool frame_case = kind == 1;
            bool& saw_failure = frame_case ? saw_frame_allocation_failure : saw_body_allocation_failure;
            std::size_t& fault_budget = frame_case ? frame_fault_budget : body_fault_budget;
            for (std::size_t budget = 0; budget < 96 && !saw_failure; ++budget) {
                scripts.load_research_script("voice_allocation_stage = -1");
                scripts.fail_next_allocation_for_test(budget);
                bool failed = false;
                try { core.dispatch({frame_case ? "writer.voice_frame_alloc" : "writer.voice_alloc",
                                     300 + budget}); }
                catch (const std::exception&) { failed = true; }
                scripts.fail_next_allocation_for_test(std::numeric_limits<std::size_t>::max());
                require(core.active(), "voice allocation failure keeps host coherent");
                scripts.load_research_script("assert(fc_research.set_text(tostring(voice_allocation_stage)))");
                if (failed && core.text() == "1") {
                    saw_failure = true;
                    fault_budget = budget;
                }
                scripts.load_research_script(R"lua(
                    local before = voice_allocation_writer:snapshot()
                    local body = fc_research.voice_message_body(voice_allocation_writer)
                    local frame = fc_research.voice_message_frame(voice_allocation_writer)
                    local after = voice_allocation_writer:snapshot()
                    assert(#body >= 17 and #body <= 34)
                    assert(frame == string.char(10, #body) .. body)
                    assert(before.data == after.data)
                    assert(before.bit_cursor == after.bit_cursor and before.overflow == after.overflow)
                )lua");
            }
        }
        require(saw_body_allocation_failure, "one-shot fault reached projected body Lua allocation");
        require(saw_frame_allocation_failure, "one-shot fault reached projected frame Lua allocation");

        core.shutdown();
        require(!core.active(), "owned writer host shuts down cleanly");
        std::cout << "lua bit writer candidate checks: " << checks
                  << "; factory fault budget: " << factory_fault_budget
                  << "; snapshot fault budget: " << snapshot_fault_budget
                  << "; body fault budget: " << body_fault_budget
                  << "; frame fault budget: " << frame_fault_budget << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "lua bit writer candidate test failed: " << error.what() << '\n';
        return 1;
    }
}
