#include "fc/mock.hpp"
#include <iostream>
#include <stdexcept>

namespace {
unsigned checks{};
void require(bool value, const char* description) {
    if (!value) throw std::runtime_error(description);
    ++checks;
}
template<class Function> void rejects(Function function, const char* description) {
    bool rejected = false;
    try { function(); } catch (const std::exception&) { rejected = true; }
    require(rejected, description);
}
struct FailingScripts final : fc::ScriptHost {
    bool fail = true;
    unsigned stopped{};
    void initialize() override { if (fail) throw std::runtime_error("script init failure"); }
    void event(const fc::Event&) override { throw std::runtime_error("event failure"); }
    void shutdown() noexcept override { ++stopped; }
};
struct ReentrantScripts final : fc::ScriptHost {
    fc::Core* core{};
    bool cancel_init{};
    bool init_rejected{};
    unsigned stopped{};
    void initialize() override { if (cancel_init) core->shutdown(); }
    void event(const fc::Event&) override {}
    void shutdown() noexcept override {
        ++stopped;
        try { core->initialize(); } catch (const std::logic_error&) { init_rejected = true; }
    }
};
struct CancelOnDestroy {
    fc::Core* core{};
    fc::Core::Token* target{};
    bool* cancelled{};
    ~CancelOnDestroy() { *cancelled = core->cancel(*target); }
};
}
int main() {
    try {
        fc::ConfigDocument input;
        input.fields["setting.text"] = std::string("a\0b\nc", 5);
        input.fields["future.unknown"] = std::string("\0\xff", 2);
        const auto encoded = input.serialize();
        require(fc::ConfigDocument::parse(encoded).fields == input.fields, "binary config round trip");
        require(fc::ConfigDocument::parse("").fields.empty(), "empty config is defaults");
        rejects([] { fc::ConfigDocument::parse("not a config"); }, "reject historic/unrecognized documents");
        rejects([] { fc::ConfigDocument::parse("FCFG/1\n1 0\na\n1 0\na\n"); }, "reject duplicate keys");
        rejects([] { fc::ConfigDocument::parse("FCFG/1\n999999999999999999999 1\na\n"); }, "reject length overflow");
        rejects([] { fc::ConfigDocument::parse("FCFG/1\n0 0\n\n"); }, "reject empty key");
        rejects([] { fc::ConfigDocument::parse("FCFG/1\n1 2\naX\n"); }, "reject truncation");
        rejects([] { fc::ConfigDocument::parse(std::string(fc::ConfigDocument::max_bytes + 1, 'x')); }, "reject oversized input");
        for (std::size_t size = 1; size < encoded.size(); ++size) {
            // Record boundaries and bare magic can be valid prefixes; every accepted prefix must round trip.
            try {
                const auto parsed = fc::ConfigDocument::parse(std::string_view(encoded).substr(0, size));
                require(fc::ConfigDocument::parse(parsed.serialize()).fields == parsed.fields, "valid prefix round trip");
            } catch (const std::invalid_argument&) {}
        }
        fc::MockEngine engine;
        fc::MockScripts scripts;
        fc::RecordingRenderer renderer;
        fc::Core core(engine, scripts, renderer);
        rejects([&] { core.dispatch({"event", 0}); }, "inactive dispatch rejected");
        rejects([&] { core.initialize("bad"); }, "failed load rejected");
        require(!core.active() && scripts.stops == 0, "parse failure never starts adapters");
        core.initialize(encoded);
        require(core.profile().mock && core.profile().source_revision == 8413246, "mock profile labeled");
        require(core.text() == input.fields.at("setting.text"), "load text bytes");
        require(renderer.frames.back().second == core.text(), "initial setting presented");
        rejects([&] { core.initialize(); }, "double initialization rejected");
        core.override_text("override", 9);
        core.clear_owner(8);
        require(core.text() == "override", "other owner cannot clear override");
        require(fc::ConfigDocument::parse(core.save()).fields == input.fields, "save uses stored value and retains unknown fields");
        core.clear_owner(9);
        require(core.text() == input.fields.at("setting.text"), "matching owner clears override");
        core.override_text("override", 9);
        core.set_text("persisted");
        require(core.text() == "persisted", "stored write clears override");
        std::vector<int> mutable_counts;
        const auto mutable_callback = core.subscribe([&, count = 0](const fc::Event&) mutable {
            mutable_counts.push_back(++count);
        });
        core.dispatch({"mutable", 0});
        core.dispatch({"mutable", 1});
        core.cancel(mutable_callback);
        require(mutable_counts == std::vector<int>({1, 2}), "mutable closure state persists across events");
        std::vector<int> order;
        fc::Core::Token second{};
        const auto first = core.subscribe([&](const fc::Event&) {
            order.push_back(1);
            core.cancel(second);
            core.subscribe([&](const fc::Event&) { order.push_back(3); });
        });
        second = core.subscribe([&](const fc::Event&) { order.push_back(2); });
        core.dispatch({"event", 1});
        require(order == std::vector<int>{1}, "cancel pending callback and defer new registration");
        core.cancel(first);
        core.dispatch({"event", 2});
        require(order == std::vector<int>({1, 3}), "new callback runs next event");
        auto captured = std::make_shared<int>(1);
        std::weak_ptr<int> weak = captured;
        const auto owning = core.subscribe([captured](const fc::Event&) {});
        captured.reset();
        core.cancel(owning);
        require(weak.expired(), "cancellation releases captured ownership");
        const auto recursive = core.subscribe([&](const fc::Event&) { core.dispatch({"recursive", 3}); });
        rejects([&] { core.dispatch({"event", 3}); }, "recursive dispatch rejected");
        core.cancel(recursive);
        core.dispatch({"after-error", 4});
        require(core.active(), "dispatch guard restored after exception");
        core.reset_device();
        require(renderer.resets == 1 && renderer.frames.back().second == "persisted", "reset redraws current setting");
        core.subscribe([&](const fc::Event&) { core.shutdown(); });
        core.subscribe([&](const fc::Event&) { throw std::runtime_error("stale callback"); });
        core.dispatch({"shutdown", 5});
        require(!core.active() && !scripts.live && engine.resets == 1, "shutdown during dispatch stops remaining callbacks");
        core.shutdown();
        require(engine.resets == 1, "shutdown idempotent");
        for (unsigned cycle = 0; cycle < 100; ++cycle) {
            core.initialize();
            core.subscribe([&](const fc::Event&) { core.set_text("cycle"); });
            core.dispatch({"mock.round", cycle});
            require(core.text() == "cycle", "mock lifecycle cycle");
            core.shutdown();
        }
        require(engine.resets == 101, "100 standalone mock lifecycles complete");
        fc::ConfigDocument full;
        full.fields["setting.text"] = std::string(fc::ConfigDocument::max_bytes - 64, 'x');
        full.fields["setting.text"].append(fc::ConfigDocument::max_bytes - full.serialize().size(), 'x');
        require(full.serialize().size() == fc::ConfigDocument::max_bytes, "exact document budget fixture");
        core.initialize(full.serialize());
        require(core.save().size() == fc::ConfigDocument::max_bytes, "exact budget config can save");
        core.override_text("retained override", 1);
        rejects([&] { core.set_text(std::string(fc::ConfigDocument::max_bytes, 'x')); }, "unsavable edit rejected");
        require(core.text() == "retained override" && core.save().size() == fc::ConfigDocument::max_bytes,
                "rejected edit preserves stored text and override");
        core.shutdown();
        full.fields.clear();
        full.fields["unknown"] = std::string(fc::ConfigDocument::max_bytes - 64, 'x');
        full.fields["unknown"].append(fc::ConfigDocument::max_bytes - full.serialize().size(), 'x');
        const auto before_stops = scripts.stops;
        rejects([&] { core.initialize(full.serialize()); }, "reject load if default insertion exceeds output budget");
        require(!core.active() && scripts.stops == before_stops, "budget rejection occurs before adapters start");
        ReentrantScripts reentrant;
        fc::Core reentrant_core(engine, reentrant, renderer);
        reentrant.core = &reentrant_core;
        reentrant.cancel_init = true;
        rejects([&] { reentrant_core.initialize(); }, "shutdown during initialization cancels transaction");
        require(!reentrant_core.active() && reentrant.init_rejected && reentrant.stopped == 1,
                "cancelled init cleans up and prevents reentrant init during teardown");
        reentrant.cancel_init = false;
        reentrant.init_rejected = false;
        reentrant_core.initialize();
        reentrant_core.shutdown();
        require(!reentrant_core.active() && reentrant.init_rejected, "shutdown adapter cannot reinitialize core");
        core.initialize();
        fc::Core::Token nested_target{};
        bool nested_cancelled{};
        auto cancel_capture = std::make_shared<CancelOnDestroy>();
        cancel_capture->core = &core;
        cancel_capture->target = &nested_target;
        cancel_capture->cancelled = &nested_cancelled;
        const auto holder = core.subscribe([cancel_capture](const fc::Event&) {});
        nested_target = core.subscribe([](const fc::Event&) {});
        cancel_capture.reset();
        require(core.cancel(holder) && nested_cancelled && !core.cancel(nested_target),
                "capture destructor can cancel another node after stable erase");
        nested_cancelled = true;
        cancel_capture = std::make_shared<CancelOnDestroy>();
        cancel_capture->core = &core;
        cancel_capture->target = &nested_target;
        cancel_capture->cancelled = &nested_cancelled;
        core.subscribe([cancel_capture](const fc::Event&) {});
        nested_target = core.subscribe([](const fc::Event&) {});
        cancel_capture.reset();
        core.shutdown();
        require(!nested_cancelled && !core.active(), "shutdown releases captures after detaching subscription vector");
        FailingScripts failing;
        fc::Core failure(engine, failing, renderer);
        rejects([&] { failure.initialize(); }, "script init failure propagated");
        require(!failure.active() && failing.stopped == 1, "partial initialization cleaned up");
        failing.fail = false;
        failure.initialize();
        rejects([&] { failure.dispatch({"error", 0}); }, "script event error propagated");
        failure.shutdown();
        std::cout << "{\"passed\":true,\"checks\":" << checks
                  << ",\"mock_lifecycle_cycles\":100,\"reference_comparison\":false}\n";
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
