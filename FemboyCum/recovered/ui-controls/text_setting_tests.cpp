#include "text_setting.hpp"
#include <iostream>
#include <vector>
using femboylose::recovered::TextSetting;
int main() {
    unsigned checks=0;
    const auto require=[&](bool ok,const char* name) {
        if(!ok) throw std::runtime_error(name);
        ++checks;
    };
    std::vector<std::string> order;
    TextSetting t("initial",[&]{order.push_back("notify");},
                  [&]{order.push_back("related78");},[&]{order.push_back("related74");});
    require(t.stored()=="initial" && t.initial()=="initial","initial copy");
    require(!t.override_value() && t.owner_token()==0,"initial override absence");
    t.write(std::string("temporary"),true,7);
    require(t.stored()=="initial" && t.effective_fields()=="temporary","stored/effective split");
    require(order.empty(),"override does not notify boundary");
    require(t.export_value_leaf()==std::make_pair(std::string("277698370"),std::string("initial")),"export stored only");
    t.clear_for_owner(8);
    require(t.override_value().has_value(),"foreign owner retains override");
    t.clear_for_owner(7);
    require(!t.override_value() && t.owner_token()==7,"owner cleanup retains token field");
    t.write(std::string(),true,0);
    require(t.override_value().has_value() && t.effective_fields().empty(),"empty override present");
    t.clear_for_owner(0);
    require(!t.override_value(),"zero owner is supported");
    t.write(std::string("initial"),true,3);
    require(!t.retain_distinct_override() && !t.override_value(),"equal override removed by query");
    t.write(std::string("different"),true,4);
    require(t.retain_distinct_override() && t.override_value().has_value(),"different override retained");
    for(const auto& value : {TextSetting::Value{true},TextSetting::Value{std::int64_t{9}},TextSetting::Value{std::monostate{}}}) {
        t.write(std::string("previous"),true,7);
        bool threw=false;try{t.write(value);}catch(const std::invalid_argument&){threw=true;}
        require(threw && !t.override_value() && t.stored()=="initial","invalid stored write clears override first");
        t.write(std::string("previous"),true,7);
        threw=false;try{t.write(value,true,99);}catch(const std::invalid_argument&){threw=true;}
        require(threw && !t.override_value() && t.owner_token()==7,"invalid override write retains old owner token");
    }
    require(order.empty(),"invalid writes do not notify boundary");
    t.write(std::string("stored"));
    require(order==std::vector<std::string>{"notify"},"stored write notification boundary");
    order.clear();t.write(std::string("stored"));
    require(order==std::vector<std::string>{"notify"},"equal stored write still reaches boundary");
    order.clear();t.write(std::string("override"),true,8);t.reset();
    require(t.stored()=="initial" && !t.override_value(),"reset restores caller default");
    require(order==std::vector<std::string>{"related78","related74","notify"},"reset dispatch order");
    order.clear();t.reset();
    require(order.size()==3,"repeated reset still dispatches");
    t.write(std::string("new default"));t.write(std::string("ignored override"),true,8);
    order.clear();t.capture_default();
    require(t.initial()=="new default" && t.override_value().has_value() && order.empty(),"capture stored default without notify or override clear");
    t.reset();require(t.stored()=="new default","captured default used on reset");
    t.write(std::string("override"),true,8);order.clear();t.import_value_prefix(std::nullopt);
    require(t.stored()=="new default" && !t.override_value() && order.empty(),"missing import prefix clears override preserves stored");
    t.import_value_prefix(TextSetting::Value{std::string("imported")});
    require(t.stored()=="imported" && t.initial()=="new default","import does not replace default");
    t.write(std::string("override"),true,8);
    bool threw=false;try{t.import_value_prefix(TextSetting::Value{std::int64_t{1}});}catch(const std::invalid_argument&){threw=true;}
    require(threw && !t.override_value() && t.stored()=="imported","bad import clears override before error");
    const std::string bytes("a\0b",3);t.write(bytes);
    require(t.stored().size()==3 && t.export_value_leaf().second==bytes,"stored string preserves embedded zero bytes");
    t.write(std::string(600,'x'));
    require(t.stored().size()==600,"512 editor buffer is not a proven Lua-storage cap");
    std::cout<<"{\"passed\":true,\"semantic_checks\":"<<checks<<",\"target_code_executed\":false}\n";
}
