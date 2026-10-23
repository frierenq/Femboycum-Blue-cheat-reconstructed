#pragma once
#include "fc/config.hpp"
#include "fc/bruteforce.hpp"
#include "fc/records.hpp"
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <utility>

namespace fc {
struct EngineProfile {
    std::string id;
    std::string patch;
    std::uint32_t source_revision{};
    bool mock{};
};
struct Event { std::string name; std::uint64_t tick{}; };
class EngineAdapter {
public:
    virtual ~EngineAdapter() = default;
    virtual EngineProfile profile() const = 0;
    virtual void reset() noexcept = 0;
};
class ScriptHost {
public:
    virtual ~ScriptHost() = default;
    virtual void initialize() = 0;
    virtual void event(const Event&) = 0;
    virtual void shutdown() noexcept = 0;
};
class Renderer {
public:
    virtual ~Renderer() = default;
    virtual void setting(std::string_view key, std::string_view value) = 0;
    virtual void reset_device() = 0;
    virtual void shutdown() noexcept = 0;
};

// Single-threaded, caller-owned adapters must outlive Core. No game pointers.
class Core {
public:
    using Token = std::uint64_t;
    using Callback = std::function<void(const Event&)>;
    Core(EngineAdapter&, ScriptHost&, Renderer&);
    ~Core();
    Core(const Core&) = delete;
    Core& operator=(const Core&) = delete;
    void initialize(std::string_view config = {});
    void shutdown() noexcept;
    bool active() const noexcept;
    EngineProfile profile() const;
    void set_text(std::string value);
    void override_text(std::string value, std::uint32_t owner);
    void clear_owner(std::uint32_t owner);
    std::string text() const;
    std::string save() const;
    void render();
    void reset_device();
    Token subscribe(Callback);
    bool cancel(Token);
    void dispatch(const Event&);
    // Explicit research-tail replay, separate from unverified native event routing.
    void research_hurt_tail(EntitySlot, std::int32_t supplied_random_word);
    // One explicit owned default-stream projection, shared across these research calls.
    void research_random_seed(std::int32_t);
    std::int32_t research_random_int(std::int32_t low, std::int32_t high);
    float research_random_float(float low, float high);
    float research_random_float_exp(float low, float high, float exponent);
    std::uint64_t research_random_generation_count() const;
    void research_hurt_profile_rng(EntitySlot);
    void research_feedback_tail(RecordSlot, std::optional<FeedbackTiming>);
    void research_reset_arrays();
    std::pair<std::uint32_t, std::uint32_t> research_state(EntitySlot) const;
    void research_seed_record(std::uint32_t slot, RecordSlice record);
    RecordSlice research_record(std::uint32_t slot) const;
    void research_set_table_word(std::uint32_t slot, std::uint32_t value);
    std::uint32_t research_table_word(std::uint32_t slot) const;
    void research_round_cleanup();
    DeathCleanupResult research_death_cleanup(ResourceToken victim, ResourceToken reloaded_local,
                                               std::uint32_t first_index, std::uint32_t second_index);
    std::string research_record_trace() const;
private:
    struct State;
    struct Subscription { Token token; Callback callback; };
    void require_active() const;
    EngineAdapter& engine_;
    ScriptHost& scripts_;
    Renderer& renderer_;
    std::unique_ptr<State> state_;
    std::vector<std::shared_ptr<Subscription>> subscriptions_;
    Token next_token_ = 1;
    bool dispatching_ = false;
    bool initializing_ = false;
    bool initialization_cancelled_ = false;
    bool stopping_ = false;
    std::uint64_t generation_ = 0;
};
}
