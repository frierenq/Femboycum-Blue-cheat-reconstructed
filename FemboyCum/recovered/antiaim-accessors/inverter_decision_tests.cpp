#include "inverter_decision.hpp"
#include <algorithm>
#include <cstdlib>
#include <deque>
#include <iostream>
#include <map>
#include <string>
#include <utility>
#include <vector>
using namespace femboylose::recovered;
using Route=InverterDecisionRoute;
static unsigned checks=0;
static void expect(bool condition){
    ++checks;
    if(!condition){std::cerr<<"failed check "<<checks<<'\n';std::exit(1);}
}
static constexpr std::uint32_t context=0x100000u,config=0x200000u,config2=0x300000u,engine=0x400000u;
struct Fixture final:InverterDecisionData {
    std::map<std::uint32_t,std::uint8_t> bytes;
    std::map<std::uint32_t,std::uint32_t> words;
    std::map<std::uint32_t,std::deque<std::uint32_t>> scripted_words;
    std::vector<std::pair<char,std::uint32_t>> reads;
    std::vector<std::string> effects;
    std::int32_t random_result=0;
    Fixture(){
        words[context+0x40u]=1;words[0x424f4b18u]=2;bytes[context+0x44u]=0;
        words[0x424f639cu]=config;set_config(config,0);
        words[context]=2;set_float(context+4u,std::numeric_limits<float>::max());
        words[context+0x10u]=0;set_float(context+0x14u,30);set_float(context+0x20u,0);
        bytes[0x424b1c9du]=0;words[0x4223bef4u]=0;
        words[0x4223f428u]=engine;words[engine+0x4d2cu]=43;
    }
    void set_config(std::uint32_t address,std::uint32_t bits){
        bytes[address+0x16e9cu]=0;words[address+0x16e94u]=bits;words[address+0x16e98u]=bits;
        bytes[address+0x17286u]=1;bytes[address+0x17285u]=0;bytes[address+0x17284u]=0;
        bytes[address+0x170a6u]=1;bytes[address+0x170a5u]=0;bytes[address+0x170a4u]=0;
        bytes[address+0x16fa4u]=0;words[address+0x16f9cu]=0;
        bytes[address+0x16b76u]=1;bytes[address+0x16b75u]=0;bytes[address+0x16b74u]=0;
    }
    void set_float(std::uint32_t address,float value){
        std::uint32_t bits;std::memcpy(&bits,&value,sizeof(bits));words[address]=bits;
    }
    std::uint8_t byte(std::uint32_t address)override{
        reads.emplace_back('b',address);return bytes.at(address);
    }
    std::uint32_t word(std::uint32_t address)override{
        reads.emplace_back('w',address);
        auto p=scripted_words.find(address);
        if(p!=scripted_words.end() && !p->second.empty()){
            const auto result=p->second.front();p->second.pop_front();return result;
        }
        return words.at(address);
    }
    void random_seed(std::uint32_t seed)override{effects.push_back("seed:"+std::to_string(seed));}
    std::int32_t random_int(std::int32_t low,std::int32_t high)override{
        effects.push_back("range:"+std::to_string(low)+":"+std::to_string(high));return random_result;
    }
    unsigned count(char kind,std::uint32_t address)const{
        return static_cast<unsigned>(std::count(reads.begin(),reads.end(),std::make_pair(kind,address)));
    }
};
static void result(Fixture& data,float expected,Route route,float angle=0){
    const auto actual=inverter_decision(data,context,angle);
    expect(actual.value==expected && actual.route==route);
}
int main(){
    expect(wrapped_angle_difference(180,0)==180);
    expect(wrapped_angle_difference(-180,0)==-180);
    expect(wrapped_angle_difference(540,0)==180);
    expect(wrapped_angle_difference(180,-180)==0 && !std::signbit(wrapped_angle_difference(180,-180)));
    expect(wrapped_angle_difference(-180,180)==0 && std::signbit(wrapped_angle_difference(-180,180)));
    expect(wrapped_angle_difference(16777216.0f,0.5f)==135.5f);
    expect(wrapped_angle_difference(std::numeric_limits<float>::infinity(),90)==-90);
    expect(wrapped_angle_difference(std::numeric_limits<float>::quiet_NaN(),std::numeric_limits<float>::infinity())==0);
    {
        Fixture f;f.words[0x424f4b18u]=1;result(f,60,Route::MatchingRequest);
        expect(f.count('w',0x424f639cu)==0 && f.effects.empty());
        f.bytes[context+0x44u]=255;result(f,-60,Route::MatchingRequest);
    }
    for(const std::uint32_t entry:{1u,2u,0xffffffffu}){
        Fixture f;f.set_config(config,8);f.bytes[0x424b1c9du]=1;f.words[0x4223bef4u]=4;
        f.words[context+0x1a4u+16u]=entry;result(f,entry==1?-60.0f:60.0f,Route::PerEntity);
        expect(f.count('b',config+0x17286u)==0 && f.effects.empty());
    }
    {
        Fixture f;f.set_config(config,8);f.bytes[0x424b1c9du]=1;f.words[0x4223bef4u]=4;
        f.words[context+0x1a4u+16u]=0;result(f,60,Route::ConfiguredDefault);
    }
    for(const std::uint32_t index:{0u,0xffffffffu}){
        Fixture f;f.set_config(config,8);f.bytes[0x424b1c9du]=1;f.words[0x4223bef4u]=index;
        result(f,60,Route::ConfiguredDefault);
    }
    {
        Fixture f;f.set_config(config,8);result(f,60,Route::ConfiguredDefault);
        expect(f.count('w',0x4223bef4u)==0);
    }
    for(const std::uint32_t option:{1u,2u,3u})for(const std::uint32_t state:{0u,1u}){
        Fixture f;f.words[config+0x16f9cu]=option;f.words[context]=state;
        const float base=state==0?60.0f:-60.0f;result(f,option==2?base:-base,Route::SmallState);
    }
    for(const std::uint32_t state:{2u,0xffffffffu}){
        Fixture f;f.words[config+0x16f9cu]=1;f.words[context]=state;result(f,60,Route::ConfiguredDefault);
    }
    {
        Fixture f;f.words[config+0x16f9cu]=0xffffffffu;f.words[context]=0;result(f,60,Route::ConfiguredDefault);
        expect(f.count('w',context)==0);
    }
    {
        Fixture f;f.bytes[config+0x17285u]=1;f.bytes[config+0x170a5u]=1;
        f.words[context]=0;f.words[config+0x16f9cu]=2;f.set_float(context+4u,0);
        result(f,-60,Route::SmallState);
    }
    for(const float value:{std::numeric_limits<float>::quiet_NaN(),std::numeric_limits<float>::max()}){
        Fixture f;f.bytes[config+0x17285u]=1;f.bytes[config+0x170a5u]=1;
        f.words[context]=0;f.set_float(context+4u,value);result(f,60,Route::ConfiguredDefault);
    }
    {
        Fixture f;f.bytes[config+0x17285u]=1;f.bytes[config+0x170a5u]=1;
        f.words[context]=0;f.set_float(context+4u,std::numeric_limits<float>::infinity());
        result(f,-60,Route::SmallState);
    }
    {
        Fixture f;f.bytes[config+0x17286u]=0;f.bytes[config+0x17285u]=0;f.bytes[config+0x17284u]=9;
        f.bytes[config+0x170a6u]=255;f.bytes[config+0x170a5u]=8;
        f.words[context]=1;f.set_float(context+4u,3);result(f,60,Route::SmallState);
        expect(f.count('b',config+0x17284u)==1 && f.count('b',config+0x17285u)==0);
    }
    {
        Fixture f;result(f,60,Route::ConfiguredDefault);
        expect(f.count('b',config+0x170a6u)==0 && f.count('w',context+4u)==0);
    }
    {
        Fixture f;f.bytes[config+0x16fa4u]=7;f.words[config+0x16f9cu+28u]=2;f.words[context]=0;
        result(f,60,Route::SmallState);
        expect(f.count('w',config+0x16f9cu)==0 && f.count('w',config+0x16f9cu+28u)==1);
    }
    for(const std::uint32_t parity:{0u,1u,2u,3u,0xffffffffu,0x80000001u,0x80000000u,0x7fffffffu}){
        Fixture f;f.set_config(config,2);f.words[context+0x10u]=parity;
        const bool positive_odd=(parity&0x80000000u)==0 && (parity&1u)!=0;
        result(f,positive_odd?60.0f:-60.0f,Route::SignedParity);
    }
    {
        Fixture f;f.words[config+0x16e98u]=2;f.bytes[config+0x16e9cu]=255;f.words[context+0x10u]=1;
        result(f,60,Route::SignedParity);
        expect(f.count('w',config+0x16e94u)==1 && f.count('w',config+0x16e98u)==1);
    }
    for(const std::int32_t random_value:{0,1,-1,4}){
        Fixture f;f.set_config(config,6);f.random_result=random_value;
        result(f,random_value==0?60.0f:-60.0f,Route::ExternalRandom);
        expect(f.effects==std::vector<std::string>{"seed:43","range:0:1"});
    }
    {
        Fixture f;f.set_config(config,4);result(f,60,Route::ConfiguredDefault);expect(f.effects.empty());
    }
    {
        Fixture f;f.set_config(config,15);f.bytes[0x424b1c9du]=1;f.words[0x4223bef4u]=4;
        f.words[context+0x1a4u+16u]=1;f.words[context]=0;f.words[config+0x16f9cu]=1;
        result(f,-60,Route::PerEntity);expect(f.effects.empty());
    }
    {
        Fixture f;f.set_config(config,7);f.set_float(context+0x20u,30);
        result(f,60,Route::MinusMetric);expect(f.count('w',0x424f639cu)==1 && f.effects.empty());
    }
    {
        Fixture f;f.set_config(config,1);f.set_float(context+0x20u,-30);result(f,-60,Route::PlusMetric);
    }
    for(const float reference:{0.0f,10.0f,-10.0f}){
        Fixture f;f.set_config(config,1);f.set_float(context+0x20u,reference);
        result(f,60,Route::ConfiguredDefault);expect(f.count('w',0x424f639cu)==2);
    }
    for(const float reference:{10.001f,-10.001f}){
        Fixture f;f.set_config(config,1);f.set_float(context+0x20u,reference);
        result(f,reference>0?60.0f:-60.0f,reference>0?Route::MinusMetric:Route::PlusMetric);
    }
    {
        Fixture f;f.set_config(config,1);f.set_float(context+0x20u,60);result(f,60,Route::MinusMetric,390);
    }
    {
        Fixture f;f.set_config(config,1);f.set_float(context+0x20u,30);
        result(f,60,Route::MinusMetric,std::numeric_limits<float>::quiet_NaN());
    }
    {
        Fixture f;f.set_config(config,1);f.set_float(context+0x14u,std::numeric_limits<float>::infinity());
        result(f,60,Route::ConfiguredDefault);
    }
    {
        Fixture f;f.set_config(config,1);f.set_config(config2,2);f.words[context+0x10u]=1;
        f.scripted_words[0x424f639cu]={config,config2};result(f,60,Route::SignedParity);
        expect(f.scripted_words[0x424f639cu].empty());
    }
    {
        Fixture f;f.set_config(config,1);f.set_config(config2,0);f.bytes[config2+0x16b75u]=1;
        f.scripted_words[0x424f639cu]={config,config2};result(f,-60,Route::ConfiguredDefault);
        expect(f.count('b',config+0x16b76u)==0 && f.count('b',config2+0x16b76u)==1);
    }
    {
        Fixture f;f.scripted_words[0x424f4b18u]={2,1};f.bytes[context+0x44u]=1;result(f,-60,Route::LateRequest);
    }
    {
        Fixture f;f.scripted_words[context+0x40u]={1,2};result(f,60,Route::LateRequest);
    }
    {
        Fixture f;f.bytes[context+0x44u]=255;result(f,60,Route::ConfiguredDefault);
        expect(f.count('b',context+0x44u)==0);
    }
    {
        Fixture f;f.bytes[config+0x16b76u]=0;f.bytes[config+0x16b74u]=7;result(f,-60,Route::ConfiguredDefault);
        expect(f.count('b',config+0x16b75u)==0);
    }
    std::cout<<"{\"passed\":true,\"semantic_checks\":"<<checks
        <<",\"model\":\"analyst-authored local inverter decision tree with supplied data and external RNG\","
        "\"target_runtime_executed\":false,\"external_rng_reimplemented\":false,"
        "\"whole_inverter_lifecycle_recovered\":false}\n";
}
