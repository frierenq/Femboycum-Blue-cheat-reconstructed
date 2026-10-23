#include "inverter_request.hpp"
#include <cstdlib>
#include <iostream>
#include <limits>
using namespace femboylose::recovered;
static unsigned checks=0;
static void expect(bool condition){
    ++checks;
    if(!condition){std::cerr<<"failed check "<<checks<<'\n';std::exit(1);}
}
int main(){
    InverterRequestState context{7,100,0};
    expect(!matching_inverter_request_block(context,99));
    expect(!matching_inverter_request_block(context,101));
    expect(matching_inverter_request_block(context,100)==60.0f);
    expect(context.active==7 && context.request_counter==100 && context.request_value==0);
    context.request_value=1;
    expect(matching_inverter_request_block(context,100)==-60.0f);
    context.request_value=255;
    expect(matching_inverter_request_block(context,100)==-60.0f);
    expect(matching_inverter_request_block(context,100)==-60.0f);
    expect(context.active==7 && context.request_counter==100 && context.request_value==255);
    // Combining the separately recovered request writer and matching read gate.
    record_inverter_request(context,0,1,31,90,80);
    expect(context.active==7 && context.request_counter==31 && context.request_value==0);
    const auto false_result=matching_inverter_request_block(context,31);
    expect(false_result==60.0f);
    expect(inverter_active_from_result_block(*false_result)==0);
    record_inverter_request(context,1,9,31,90,80);
    const auto true_result=matching_inverter_request_block(context,31);
    expect(true_result==-60.0f);
    expect(inverter_active_from_result_block(*true_result)==1);
    expect(context.active==7);
    expect(!matching_inverter_request_block(context,32));
    // Prediction counter addition is unsigned modulo 2^32, with equality only.
    record_inverter_request(context,1,0,999,0xffffffffu,0);
    expect(context.request_counter==0 && context.active==7);
    expect(!matching_inverter_request_block(context,0xffffffffu));
    expect(matching_inverter_request_block(context,0)==-60.0f);
    expect(!matching_inverter_request_block(context,1));
    record_inverter_request(context,0,0,999,0xfffffffeu,0);
    expect(context.request_counter==0xffffffffu);
    expect(matching_inverter_request_block(context,0xffffffffu)==60.0f);
    // The initialized -1 word is a matching value if the compared counter is -1.
    const InverterRequestState initialized{0,0xffffffffu,0};
    expect(matching_inverter_request_block(initialized,0xffffffffu)==60.0f);
    expect(!matching_inverter_request_block(initialized,0));
    expect(inverter_active_from_result_block(0.0f)==0);
    expect(inverter_active_from_result_block(-0.0f)==0);
    expect(inverter_active_from_result_block(60.0f)==0);
    expect(inverter_active_from_result_block(-60.0f)==1);
    expect(inverter_active_from_result_block(std::numeric_limits<float>::infinity())==0);
    expect(inverter_active_from_result_block(-std::numeric_limits<float>::infinity())==1);
    expect(inverter_active_from_result_block(std::numeric_limits<float>::quiet_NaN())==1);
    expect(inverter_active_from_result_block(-std::numeric_limits<float>::quiet_NaN())==1);
    expect(inverter_active_from_result_block(std::numeric_limits<float>::denorm_min())==0);
    expect(inverter_active_from_result_block(-std::numeric_limits<float>::denorm_min())==1);
    std::cout<<"{\"passed\":true,\"semantic_checks\":"<<checks
        <<",\"model\":\"analyst-authored inverter request-match and active-sign blocks\","
        "\"target_runtime_executed\":false,\"whole_inverter_lifecycle_recovered\":false}\n";
}
