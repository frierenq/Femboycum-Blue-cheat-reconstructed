#include "fc/core.hpp"
#include "fc/uniform_random.hpp"
#include "text_setting.hpp"
#include <algorithm>
#include <limits>
#include <stdexcept>
#include <utility>

namespace fc {
namespace {
struct RecordTrace final : RecordEffects {
    std::vector<std::string> operations;
    void observed_write(ObservedField field, std::size_t slot, std::uint64_t value) override {
        operations.push_back("{\"kind\":\"write\",\"field\":" + std::to_string(static_cast<unsigned>(field)) +
            ",\"slot\":" + std::to_string(slot) + ",\"value\":" + std::to_string(value) + "}");
    }
    void release_entry(ResourceToken token, std::uint32_t first, std::uint32_t second) override {
        operations.push_back("{\"kind\":\"release_entry\",\"token\":" + std::to_string(token) +
            ",\"literal_a\":" + std::to_string(first) + ",\"literal_b\":" + std::to_string(second) + "}");
    }
    void release_storage(ResourceToken token, std::uint32_t size) override {
        operations.push_back("{\"kind\":\"release_storage\",\"token\":" + std::to_string(token) +
            ",\"bytes\":" + std::to_string(size) + "}");
    }
};
void check_record_slot(std::uint32_t slot) {
    if (slot >= RecordBank::slot_count) throw std::invalid_argument("record bank slot must be in 0..64");
}
}
struct Core::State {
    ConfigDocument document;
    femboylose::recovered::TextSetting setting{"Source-owned research"};
    OwnedBruteforceStore bruteforce;
    ProfileUniformRandom research_random;
    RecordBank records;
    RecordTrace record_trace;
};
Core::Core(EngineAdapter& engine, ScriptHost& scripts, Renderer& renderer)
    : engine_(engine), scripts_(scripts), renderer_(renderer) {}
Core::~Core() { shutdown(); }
bool Core::active() const noexcept { return bool(state_) && !initializing_; }
void Core::require_active() const {
    if (!active()) throw std::logic_error("core is not initialized");
}
void Core::initialize(std::string_view input) {
    if (state_ || initializing_ || stopping_ || dispatching_) throw std::logic_error("core cannot initialize now");
    auto staged = std::make_unique<State>();
    staged->document = ConfigDocument::parse(input);
    const auto found = staged->document.fields.find("setting.text");
    if (found != staged->document.fields.end())
        staged->setting.import_value_prefix(femboylose::recovered::TextSetting::Value{found->second});
    // Every accepted state must fit the same output budget, including inserted defaults.
    staged->document.fields["setting.text"] = staged->setting.stored();
    (void)staged->document.serialize();
    initializing_ = true;
    initialization_cancelled_ = false;
    try {
        scripts_.initialize();
        if (initialization_cancelled_) throw std::logic_error("initialization cancelled");
        renderer_.setting("setting.text", staged->setting.effective_fields());
        if (initialization_cancelled_) throw std::logic_error("initialization cancelled");
        state_ = std::move(staged);
        ++generation_;
        initializing_ = false;
    } catch (...) {
        stopping_ = true;
        scripts_.shutdown();
        renderer_.shutdown();
        engine_.reset();
        stopping_ = false;
        initializing_ = false;
        throw;
    }
}
void Core::shutdown() noexcept {
    if (initializing_) { initialization_cancelled_ = true; return; }
    if (!state_) return;
    stopping_ = true;
    std::vector<std::shared_ptr<Subscription>> retired;
    retired.swap(subscriptions_);
    state_.reset();
    ++generation_;
    // Captured destructors may reenter cancel(); the member container is already empty.
    retired.clear();
    scripts_.shutdown();
    renderer_.shutdown();
    engine_.reset();
    stopping_ = false;
}
EngineProfile Core::profile() const { return engine_.profile(); }
void Core::set_text(std::string value) {
    require_active();
    auto document = state_->document;
    document.fields["setting.text"] = value;
    (void)document.serialize();
    state_->setting.write(std::move(value));
}
void Core::override_text(std::string value, std::uint32_t owner) {
    require_active();
    state_->setting.write(std::move(value), true, owner);
}
void Core::clear_owner(std::uint32_t owner) {
    require_active();
    state_->setting.clear_for_owner(owner);
}
std::string Core::text() const {
    require_active();
    return state_->setting.effective_fields();
}
std::string Core::save() const {
    require_active();
    auto document = state_->document;
    document.fields["setting.text"] = state_->setting.stored();
    return document.serialize();
}
void Core::render() {
    require_active();
    // Own the rendered bytes across a renderer callback that may request shutdown.
    const auto value = text();
    renderer_.setting("setting.text", value);
}
void Core::reset_device() { require_active(); renderer_.reset_device(); if (active()) render(); }
Core::Token Core::subscribe(Callback callback) {
    require_active();
    if (!callback) throw std::invalid_argument("empty event callback");
    if (next_token_ == std::numeric_limits<Token>::max()) throw std::overflow_error("callback token exhaustion");
    const auto token = next_token_++;
    subscriptions_.push_back(std::make_shared<Subscription>(Subscription{token, std::move(callback)}));
    return token;
}
bool Core::cancel(Token token) {
    const auto found = std::find_if(subscriptions_.begin(), subscriptions_.end(),
        [token](const auto& item) { return item->token == token; });
    if (found == subscriptions_.end()) return false;
    // Delay final callable/capture destruction until vector compaction has finished.
    auto retired = *found;
    subscriptions_.erase(found);
    return true;
}
void Core::dispatch(const Event& event) {
    require_active();
    if (dispatching_) throw std::logic_error("recursive event dispatch is unsupported");
    const auto callbacks = subscriptions_;
    const auto generation = generation_;
    dispatching_ = true;
    struct Guard { bool& flag; ~Guard() { flag = false; } } guard{dispatching_};
    scripts_.event(event);
    for (const auto& item : callbacks) {
        if (!active() || generation_ != generation) break;
        const bool registered = std::any_of(subscriptions_.begin(), subscriptions_.end(),
            [&item](const auto& current) { return current->token == item->token; });
        if (registered) item->callback(event);
    }
}
void Core::research_hurt_tail(EntitySlot slot, std::int32_t supplied_random_word) {
    require_active();
    struct SuppliedRandom final : RandomSource {
        std::int32_t value;
        explicit SuppliedRandom(std::int32_t word) : value(word) {}
        std::int32_t integer(std::int32_t, std::int32_t) override { return value; }
    } random(supplied_random_word);
    recovered_hurt_tail(state_->bruteforce, random, slot);
}
void Core::research_random_seed(std::int32_t value) {
    require_active();
    state_->research_random.seed(value);
}
std::int32_t Core::research_random_int(std::int32_t low, std::int32_t high) {
    require_active();
    return state_->research_random.integer(low, high);
}
std::uint64_t Core::research_random_generation_count() const {
    require_active();
    return state_->research_random.snapshot().generation_calls;
}
float Core::research_random_float(float low, float high) {
    require_active();
    return state_->research_random.real(low, high);
}
float Core::research_random_float_exp(float low, float high, float exponent) {
    require_active();
    return state_->research_random.real_exp(low, high, exponent);
}
void Core::research_hurt_profile_rng(EntitySlot slot) {
    require_active();
    recovered_hurt_tail(state_->bruteforce, state_->research_random, slot);
}
void Core::research_feedback_tail(RecordSlot slot, std::optional<FeedbackTiming> timing) {
    require_active();
    recovered_feedback_tail(state_->bruteforce, slot, timing);
}
void Core::research_reset_arrays() {
    require_active();
    recovered_array_reset(*state_->bruteforce.acquire());
}
std::pair<std::uint32_t, std::uint32_t> Core::research_state(EntitySlot slot) const {
    require_active();
    auto& store = state_->bruteforce;
    const auto context = store.acquire();
    return {store.read(context, StateBank::Reference, slot), store.read(context, StateBank::Selected, slot)};
}
void Core::research_seed_record(std::uint32_t slot, RecordSlice record) {
    require_active();
    check_record_slot(slot);
    if (record.storage_token && record.count > record.entries.size())
        throw std::invalid_argument("record backing tokens are incomplete");
    state_->records.records[slot] = std::move(record);
}
RecordSlice Core::research_record(std::uint32_t slot) const {
    require_active();
    check_record_slot(slot);
    return state_->records.records[slot];
}
void Core::research_set_table_word(std::uint32_t slot, std::uint32_t value) {
    require_active();
    check_record_slot(slot);
    state_->records.table[slot] = value;
}
std::uint32_t Core::research_table_word(std::uint32_t slot) const {
    require_active();
    check_record_slot(slot);
    return state_->records.table[slot];
}
void Core::research_round_cleanup() {
    require_active();
    state_->record_trace.operations.clear();
    selected_round_start_cleanup(state_->records, state_->record_trace);
}
DeathCleanupResult Core::research_death_cleanup(ResourceToken victim, ResourceToken local,
                                                std::uint32_t first, std::uint32_t second) {
    require_active();
    struct Local final : LocalIdentityProvider {
        ResourceToken token;
        explicit Local(ResourceToken value) : token(value) {}
        ResourceToken reread_local_identity() override { return token; }
    } local_provider(local);
    struct Indices final : DeathIndexProvider {
        std::uint32_t first, second;
        unsigned calls{};
        Indices(std::uint32_t a, std::uint32_t b) : first(a), second(b) {}
        std::uint32_t next_index() override {
            if (calls >= 2) throw std::logic_error("unexpected third index read");
            return calls++ ? second : first;
        }
    } indices(first, second);
    state_->record_trace.operations.clear();
    return selected_death_cleanup(state_->records, victim, local_provider, indices, state_->record_trace);
}
std::string Core::research_record_trace() const {
    require_active();
    std::string result = "[";
    for (const auto& item : state_->record_trace.operations) {
        if (result.size() > 1) result += ',';
        result += item;
    }
    return result + ']';
}
}
