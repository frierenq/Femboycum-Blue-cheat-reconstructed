#include "button_pulse.hpp"
#include <iostream>
#include <memory>
#include <stdexcept>
using femboylose::recovered::ButtonPulse;
int main(){
    unsigned checks=0;const auto require=[&](bool ok,const char* message){if(!ok)throw std::runtime_error(message);++checks;};
    unsigned immediate=0;bool observed=false;ButtonPulse* current=nullptr;
    ButtonPulse button([&]{++immediate;observed=current->native_get();});current=&button;
    require(!button.native_get() && !button.native_get(true),"both getter modes begin false");
    require(button.normal_change() && button.native_get() && observed && immediate==1,"flag set before immediate native action");
    require(button.native_get(true),"override mode does not introduce optional scalar state");
    button.normal_change();require(immediate==2 && button.native_get(),"repeated activation invokes native action while coalescing flag");
    button.native_reset_virtual();require(button.native_get() && immediate==2,"button reset virtual is no-op");
    button.registration_boundary();require(!button.native_get(),"registration cancels pending pulse before duplicate check");
    button.normal_change();button.registration_boundary();require(!button.native_get(),"same cancellation applies even when registration would be duplicate");
    button.normal_change();button.removal_boundary();require(!button.native_get(),"unsuccessful removal boundary still clears dirty");
    button.set_notification_suppressed(true);const auto before=immediate;
    require(!button.normal_change() && !button.native_get() && immediate==before,"normal notification suppressed while busy");
    button.native_writer();require(button.native_get() && immediate==before+1,"direct native writer bypasses busy guard");
    require(button.notification_suppressed(),"direct writer does not clear suppression");
    button.finish_valid_poll();require(!button.native_get(),"valid poll consumes pulse");
    button.set_notification_suppressed(false);button.normal_change();
    require(button.native_get(),"callback can observe pulse before valid poll finishes");
    button.set_notification_suppressed(true);button.native_writer();button.set_notification_suppressed(false);
    button.finish_valid_poll();require(!button.native_get(),"direct reactivation during callback is still cleared at poll end");
    ButtonPulse empty;empty.native_writer();require(empty.native_get(),"no native action required to set pulse");
    empty.finish_valid_poll();empty.finish_valid_poll();require(!empty.native_get(),"clearing clean pulse is idempotent");
    ButtonPulse* self=nullptr;ButtonPulse reentrant([&]{self->registration_boundary();});self=&reentrant;
    reentrant.native_writer();require(!reentrant.native_get(),"immediate action can clear pulse through registry boundary");
    auto token=std::make_shared<int>(4);std::weak_ptr<int> weak=token;
    {
        ButtonPulse lifetime([retained=token]{(void)retained;});token.reset();
        require(!weak.expired(),"authored callable owns captured token while button exists");
    }
    require(weak.expired(),"authored callable capture released with button");
    std::cout<<"{\"passed\":true,\"semantic_checks\":"<<checks<<",\"target_code_executed\":false}\n";
}
