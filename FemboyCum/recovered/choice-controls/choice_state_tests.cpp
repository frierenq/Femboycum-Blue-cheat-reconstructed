#include "choice_state.hpp"
#include <iostream>
using namespace femboylose::recovered;
int main(){
    unsigned checks=0;
    const auto require=[&](bool ok,const char* message){if(!ok)throw std::runtime_error(message);++checks;};
    require(ascii_choice_equal("Alpha","aLPHa"),"ASCII case folding");
    require(!ascii_choice_equal("Alpha","Alphab"),"length mismatch");
    require(ascii_choice_equal(std::string("a\0x",3),std::string("A\0y",3)),"C-string comparison stops at zero");
    require(!ascii_choice_equal(std::string(1,static_cast<char>(0xc0)),std::string(1,static_cast<char>(0xe0))),"no invented Unicode folding");
    unsigned notifications=0;
    ComboState combo({"Alpha","ALPHA","Beta"},0,[&]{++notifications;});
    require(combo.stored_label()=="Alpha" && !combo.override_label(),"combo initial getter");
    require(combo.write_label(std::string("beta"),true,7),"combo matched override");
    require(combo.stored_index()==0 && combo.override_index()==2 && combo.owner()==7 && notifications==0,"override state split");
    require(!combo.write_label(std::string("missing")),"unknown combo label no-op");
    require(combo.active() && combo.override_index()==2 && notifications==0,"unknown label retains override");
    for(const auto& value:{ChoiceValue{true},ChoiceValue{std::int64_t{1}},ChoiceValue{std::monostate{}}}){
        bool threw=false;try{combo.write_label(value);}catch(const std::invalid_argument&){threw=true;}
        require(threw && combo.active() && combo.override_index()==2,"combo bad type preserves state");
    }
    combo.write_label(std::string("alpha"));
    require(combo.stored_index()==0 && !combo.active() && notifications==1,"duplicate label first match and clear override");
    combo.write_label(std::string("ALPHA"));require(notifications==2,"same combo value reaches notification boundary");
    ComboState high({"A","B"},99);require(high.stored_label().empty(),"combo getter does not clamp high value");
    high.normalize_stored_for_draw();require(high.stored_index()==1 && high.stored_label()=="B","draw clamps high value");
    ComboState low({"A","B"},-9);require(low.stored_label().empty(),"combo negative getter");
    low.normalize_stored_for_draw();require(low.stored_index()==0,"draw clamps negative value");
    ComboState empty({},7);empty.normalize_stored_for_draw();require(empty.stored_index()==7,"empty list skips clamp");
    ComboState empty_label({""});empty_label.write_label(std::string(),true,0);
    require(empty_label.override_label().has_value() && empty_label.override_label()->empty(),"empty override label differs from absence");
    std::vector<std::string> order;
    SelectableState multi({"Alpha","ALPHA","Beta"},7,
        [&](SelectableFields&){order.push_back("before");},[&]{order.push_back("notify");});
    multi.native_write_labels({std::string("beta"),std::string("ALPHA"),std::string("missing")});
    require(multi.fields().stored==5 && !multi.fields().active,"selectable replace/OR/ignore unknown");
    require(order==std::vector<std::string>{"before","notify"},"selectable virtual boundaries");
    require(multi.selected_labels()==std::vector<std::string>{"Alpha","Beta"},"selection order and duplicate first match");
    require(multi.contains_label("ALPHA") && !multi.contains_one_based(2),"label query uses first duplicate index");
    require(multi.contains_one_based(1) && multi.contains_one_based(3) && multi.contains_one_based(33),"one-based numeric BT wraps");
    order.clear();multi.native_write_labels({std::string("Beta")},true,11);
    require(multi.fields().stored==5 && multi.fields().active && multi.fields().override_mask==4 && multi.fields().owner==11,"selectable override writes separate fields");
    require(order==std::vector<std::string>{"before"},"override omits notification boundary");
    order.clear();multi.native_write_labels({std::string("missing")},true,12);
    require(multi.fields().active && multi.fields().override_mask==0 && multi.fields().owner==12,"unknown-only override is present zero mask");
    require(!multi.contains_label("Beta",true) && multi.contains_label("Beta"),"stored and zero override queries differ");
    bool threw=false;try{multi.native_write_labels({std::string("Alpha"),std::int64_t{9}});}catch(const std::invalid_argument&){threw=true;}
    require(threw && multi.fields().stored==1 && !multi.fields().active,"failed later argument leaves prior partial stored mutation");
    require(order==std::vector<std::string>{"before","before"},"failed write omits final notify");
    order.clear();threw=false;try{multi.native_write_labels({std::string("Beta"),true},true,99);}catch(const std::invalid_argument&){threw=true;}
    require(threw && multi.fields().active && multi.fields().override_mask==4 && multi.fields().owner==99,"failed override preserves initialized owner and prior bits");
    multi.native_write_labels({},true,0);
    require(multi.fields().stored==0 && multi.fields().active && multi.fields().override_mask==0,"helper empty override range also zeros stored");
    std::vector<std::string> large;for(unsigned n=0;n<34;++n)large.push_back("L"+std::to_string(n));
    SelectableState wrapped(large);wrapped.native_write_labels({std::string("L32")});
    require(wrapped.fields().stored==1 && wrapped.selected_labels()==std::vector<std::string>{"L0","L32"},"labels beyond 32 alias register bit");
    SelectableState history({"A","B"},1,[](SelectableFields& f){f.stored=2;});
    history.native_write_labels({std::string("A")},true,5);
    require(history.fields().stored==2 && history.fields().override_mask==1,"history boundary may change stored before override write");
    unsigned update_notifies=0;
    ComboState owned({"A","B","C"},1,[&]{++update_notifies;},50);
    owned.write_label(std::string("C"),true,9);
    require(!owned.replace_labels_for_context({"X"},51) && owned.stored_label()=="B","foreign context cannot update choice list");
    require(owned.replace_labels_for_context({"C","A","B"},50),"matching script context can update choices");
    require(owned.stored_label()=="A" && owned.override_label()==std::optional<std::string>{"B"} && owned.owner()==9,"list replacement preserves numeric indices rather than labels");
    require(update_notifies==0,"choice vector replacement has no observed scalar notification");
    owned.replace_labels_for_context({},50);
    require(owned.stored_index()==1 && owned.override_index()==2 && owned.stored_label().empty(),"empty replacement preserves raw selection fields");
    SelectableState owned_multi({"A","B"},1,{}, {},60);
    owned_multi.native_write_labels({std::string("B")},true,4);
    require(!owned_multi.replace_labels_for_context({"X","Y"},61),"selectable owner gate");
    owned_multi.replace_labels_for_context({"B","A"},60);
    require(owned_multi.selected_labels()==std::vector<std::string>{"B"} && owned_multi.selected_labels(true)==std::vector<std::string>{"A"},"selectable list replacement preserves mask positions");
    std::cout<<"{\"passed\":true,\"semantic_checks\":"<<checks<<",\"target_code_executed\":false}\n";
}
