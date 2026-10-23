#include "bruteforce_state.hpp"
#include "inverter_decision.hpp"
#include <cstdlib>
#include <deque>
#include <iostream>
#include <limits>
#include <map>
#include <utility>
#include <vector>
using namespace femboylose::recovered;
static unsigned checks=0;
static void expect(bool condition){
    ++checks;
    if(!condition){std::cerr<<"failed check "<<checks<<'\n';std::exit(1);}
}
static constexpr std::uint32_t first=0x100000u,second=0x200000u,third=0x300000u,config=0x400000u;
struct Fixture final:BruteforceStateData,InverterDecisionData {
    std::map<std::uint32_t,std::uint32_t> words;
    std::map<std::uint32_t,std::uint8_t> bytes;
    std::deque<std::uint32_t> contexts;
    std::vector<std::pair<std::uint32_t,std::uint32_t>> writes;
    std::vector<std::pair<std::int32_t,std::int32_t>> random_calls;
    std::int32_t random_value=1;
    unsigned context_reads=0,seed_calls=0;
    Fixture(){words[bruteforce_context_global]=first;set_state(first,1,0,0);}
    void set_state(std::uint32_t context,std::uint32_t index,std::uint32_t reference,std::uint32_t selected){
        words[bruteforce_slot(context,index,bruteforce_reference_offset)]=reference;
        words[bruteforce_slot(context,index,bruteforce_selected_offset)]=selected;
    }
    std::uint32_t selected(std::uint32_t context=first,std::uint32_t index=1)const{
        return words.at(bruteforce_slot(context,index,bruteforce_selected_offset));
    }
    std::uint32_t reference(std::uint32_t context=first,std::uint32_t index=1)const{
        return words.at(bruteforce_slot(context,index,bruteforce_reference_offset));
    }
    std::uint32_t word(std::uint32_t address)override{
        if(address==bruteforce_context_global){
            ++context_reads;
            if(!contexts.empty()){const auto result=contexts.front();contexts.pop_front();return result;}
        }
        return words.at(address);
    }
    void write_word(std::uint32_t address,std::uint32_t value)override{writes.emplace_back(address,value);words[address]=value;}
    std::uint8_t byte(std::uint32_t address)override{return bytes.at(address);}
    void random_seed(std::uint32_t)override{++seed_calls;}
    std::int32_t random_int(std::int32_t low,std::int32_t high)override{random_calls.emplace_back(low,high);return random_value;}
    void prepare_consumer(std::uint32_t index){
        words[first+0x40u]=0xffffffffu;words[0x424f4b18u]=0;
        words[0x424f639cu]=config;bytes[config+0x16e9cu]=0;
        words[config+0x16e94u]=option_bit(BodyYawOption::AntiBruteforce);
        words[config+0x16e98u]=option_bit(BodyYawOption::AntiBruteforce);
        words[0x4223bef4u]=index;bytes[0x424b1c9du]=1;
    }
};
int main(){
    expect((_mm_getcsr()&0x7f80u)==0x1f80u);
    {
        Fixture f;hurt_state_update_block(f,1);expect(f.selected()==1 && f.reference()==0);
        expect(f.random_calls==std::vector<std::pair<std::int32_t,std::int32_t>>{{1,2}});
        expect(f.context_reads==2 && f.writes.size()==1);
        hurt_state_update_block(f,1);expect(f.selected()==2 && f.random_calls.size()==1);
        hurt_state_update_block(f,1);expect(f.selected()==1 && f.random_calls.size()==1);
    }
    {
        Fixture f;f.random_value=2;hurt_state_update_block(f,1);expect(f.selected()==2);
    }
    for(const std::uint32_t reference:{1u,2u})for(const std::uint32_t selected:{0u,1u,2u,99u}){
        Fixture f;f.set_state(first,1,reference,selected);hurt_state_update_block(f,1);
        expect(f.selected()==reference && f.reference()==reference && f.random_calls.empty());
        expect(f.writes.size()==2 && f.writes[0].second==(reference==1?2u:1u) && f.writes[1].second==reference);
        expect(f.context_reads==2);
    }
    for(const std::uint32_t invalid:{3u,0xffffffffu}){
        Fixture f;f.set_state(first,1,0,invalid);hurt_state_update_block(f,1);
        expect(f.selected()==0 && f.random_calls.empty());
        hurt_state_update_block(f,1);expect(f.selected()==1 && f.random_calls.size()==1);
    }
    for(const std::uint32_t invalid:{3u,0xffffffffu}){
        Fixture f;f.set_state(first,1,invalid,2);f.random_value=2;hurt_state_update_block(f,1);
        expect(f.selected()==2 && f.reference()==invalid && f.context_reads==3);
        expect(f.writes.size()==2 && f.writes[0].second==0 && f.writes[1].second==2);
    }
    {
        Fixture f;f.random_value=-1;hurt_state_update_block(f,1);
        expect(f.selected()==0xffffffffu); // No invented clamp on external result.
    }
    {
        Fixture f;f.set_state(first,1,1,0);f.set_state(second,1,0,1);f.contexts={first,second};
        hurt_state_update_block(f,1);expect(f.selected(first)==2 && f.selected(second)==2);
        expect(f.writes[0].first==bruteforce_slot(first,1,bruteforce_selected_offset));
        expect(f.writes[1].first==bruteforce_slot(second,1,bruteforce_selected_offset));
    }
    {
        Fixture f;f.set_state(second,1,0,99);f.contexts={first,second};f.random_value=2;
        hurt_state_update_block(f,1);expect(f.selected(first)==0 && f.selected(second)==2 && f.context_reads==2);
    }
    {
        Fixture f;f.set_state(first,1,3,99);f.set_state(second,1,0,0);f.set_state(third,1,0,99);
        f.contexts={first,second,third};hurt_state_update_block(f,1);
        expect(f.selected(first)==0 && f.selected(second)==0 && f.selected(third)==1 && f.context_reads==3);
    }
    const BruteforceTimingInputs near{10.0f,1.0f/64.0f,640};
    for(const std::uint32_t value:{0u,1u,2u,3u,0xffffffffu}){
        const auto expected=value==0?1u:(value==1?2u:(value==2?1u:0u));
        Fixture a;a.set_state(first,1,value,99);feedback_state_update_block(a,0,near);
        expect(a.reference()==expected && a.selected()==99 && a.random_calls.empty());
        Fixture b;b.set_state(first,1,99,value);feedback_state_update_block(b,0,std::nullopt);
        expect(b.selected()==expected && b.reference()==99 && b.random_calls.empty());
    }
    for(const float time:{10.25f,9.75f,std::numeric_limits<float>::infinity(),-std::numeric_limits<float>::infinity()}){
        Fixture f;f.set_state(first,1,0,0);feedback_state_update_block(f,0,BruteforceTimingInputs{time,1.0f/64.0f,640});
        expect(f.selected()==1 && f.reference()==0);
    }
    for(const float time:{std::nextafter(10.25f,10.0f),std::nextafter(9.75f,10.0f),std::numeric_limits<float>::quiet_NaN()}){
        Fixture f;feedback_state_update_block(f,0,BruteforceTimingInputs{time,1.0f/64.0f,640});
        expect(f.reference()==1 && f.selected()==0);
    }
    {
        Fixture f;feedback_state_update_block(f,0,BruteforceTimingInputs{std::numeric_limits<float>::infinity(),std::numeric_limits<float>::infinity(),1});
        expect(f.reference()==1 && f.selected()==0);
    }
    {
        Fixture f;feedback_state_update_block(f,0,BruteforceTimingInputs{-1.25f,1.0f/64.0f,-64});
        expect(f.reference()==0 && f.selected()==1);
    }
    {
        Fixture f;feedback_state_update_block(f,0,BruteforceTimingInputs{33554432.0f,1.0f/64.0f,std::numeric_limits<std::int32_t>::max()});
        expect(f.reference()==1 && f.selected()==0);
    }
    {
        Fixture f;f.set_state(first,64,0,0);feedback_state_update_block(f,63,std::nullopt);
        expect(f.selected(first,64)==1 && f.selected()==0);
        hurt_state_update_block(f,64);expect(f.selected(first,64)==2 && f.selected()==0);
    }
    {
        Fixture f;f.set_state(first,1,0,2);feedback_state_update_block(f,0,near);
        expect(f.reference()==1 && f.selected()==2);
        hurt_state_update_block(f,1);expect(f.reference()==1 && f.selected()==1);
    }
    {
        Fixture f;f.prepare_consumer(1);hurt_state_update_block(f,1);
        auto decision=inverter_decision(f,first,0);expect(decision.value==-60 && decision.route==InverterDecisionRoute::PerEntity);
        hurt_state_update_block(f,1);decision=inverter_decision(f,first,0);
        expect(decision.value==60 && decision.route==InverterDecisionRoute::PerEntity && f.seed_calls==0);
    }
    std::cout<<"{\"passed\":true,\"semantic_checks\":"<<checks
        <<",\"model\":\"analyst-authored hurt/feedback state update blocks\","
        "\"target_runtime_executed\":false,\"external_rng_reimplemented\":false,"
        "\"whole_anti_bruteforce_lifecycle_recovered\":false}\n";
}
