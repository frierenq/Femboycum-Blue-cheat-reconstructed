#pragma once
#include "fc/core.hpp"
#include <stdexcept>
#include <utility>

namespace fc {
// Test adapters. These do not claim to implement Lua, D3D9 or the game engine.
class MockEngine final : public EngineAdapter {
public:
    EngineProfile profile() const override { return {"mock", "1.38.8.1", 8413246, true}; }
    void reset() noexcept override { ++resets; }
    unsigned resets{};
};
class MockScripts final : public ScriptHost {
public:
    void initialize() override { live = true; }
    void event(const Event& e) override {
        if (!live) throw std::logic_error("script host inactive");
        events.push_back(e);
    }
    void shutdown() noexcept override { live = false; ++stops; }
    bool live{};
    unsigned stops{};
    std::vector<Event> events;
};
class RecordingRenderer final : public Renderer {
public:
    void setting(std::string_view key, std::string_view value) override {
        frames.emplace_back(std::string(key), std::string(value));
    }
    void reset_device() override { ++resets; }
    void shutdown() noexcept override { ++stops; }
    unsigned resets{}, stops{};
    std::vector<std::pair<std::string, std::string>> frames;
};
}
