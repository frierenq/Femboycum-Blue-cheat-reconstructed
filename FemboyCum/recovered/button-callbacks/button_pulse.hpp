#pragma once
#include <functional>
#include <utility>
namespace femboylose::recovered {
// Selected button-specific flag/action rules from FemboyLose nl.bin.
// External code owns the Lua callback registry, validation/poll scheduling and refs.
class ButtonPulse {
public:
    explicit ButtonPulse(std::function<void()> immediate={}) : immediate_(std::move(immediate)) {}
    bool native_get(bool /*override_mode*/=false) const noexcept {return dirty_;} //41aabc60
    void set_notification_suppressed(bool value) noexcept {suppressed_=value;}
    bool notification_suppressed() const noexcept {return suppressed_;}
    // virtual+40 ->41bbbe50,then+58 ->41ad9a10 only when not busy.
    bool normal_change() {
        if(suppressed_)return false;
        native_writer();return true;
    }
    // virtual+88 ->41ac5630 directly invokes+58,without the+60 guard.
    // The outer Lua:set overload/conversion has additional conditions,not hosted here.
    void native_writer() {
        dirty_=true;
        if(immediate_)immediate_();
    }
    // These boundaries occur before registration/removal matching,even no-op cases.
    void registration_boundary() noexcept {dirty_=false;}
    void removal_boundary() noexcept {dirty_=false;}
    // 41b4bad0 clears after valid dispatch returns,also after reported callback errors.
    // It does not clear on the separate validation-error path.
    void finish_valid_poll() noexcept {dirty_=false;}
    // Button virtual+4 points to empty412a6240;no scalar default is restored.
    void native_reset_virtual() noexcept {}
private:
    bool dirty_=false;
    bool suppressed_=false;
    std::function<void()> immediate_;
};
}
