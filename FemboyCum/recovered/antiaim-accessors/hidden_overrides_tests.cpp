#include "hidden_overrides.hpp"
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
    HiddenOverrideState state;float output=13;
    expect(!consume_hidden_yaw_block(state));
    expect(!consume_hidden_pitch_block(state,output) && output==13);
    request_hidden_yaw(state,720);expect(state.yaw_enabled==1 && state.yaw==720);
    request_hidden_pitch(state,540);expect(state.pitch_enabled==1 && state.pitch==540);
    expect(consume_hidden_yaw_block(state)==720 && state.yaw_enabled==0 && state.pitch_enabled==1);
    expect(!consume_hidden_yaw_block(state));
    expect(consume_hidden_pitch_block(state,output) && output==180 && state.pitch_enabled==0);
    expect(!consume_hidden_pitch_block(state,output) && output==180);
    request_hidden_yaw(state,10);request_hidden_yaw(state,20);
    expect(consume_hidden_yaw_block(state)==20 && state.yaw_enabled==0);
    const auto nan=std::numeric_limits<float>::quiet_NaN();
    request_hidden_yaw(state,nan);const auto yaw=consume_hidden_yaw_block(state);
    expect(yaw && std::isnan(*yaw) && state.yaw_enabled==0);
    request_hidden_pitch(state,nan);
    expect(consume_hidden_pitch_block(state,output) && output==0 && state.pitch_enabled==0);
    request_hidden_pitch(state,std::numeric_limits<float>::infinity());
    expect(consume_hidden_pitch_block(state,output) && output==0 && state.pitch_enabled==0);
    request_hidden_pitch(state,181);
    expect(consume_hidden_pitch_block(state,output) && output==-179);
    request_hidden_pitch(state,-360);
    expect(consume_hidden_pitch_block(state,output) && output==0 && std::signbit(output));
    request_hidden_yaw(state,99);request_hidden_pitch(state,88);
    state.flag_6c=state.flag_74=state.flag_7c=state.flag_90=1;
    reset_override_flags_block(state,1);
    expect(state.yaw_enabled && state.pitch_enabled && state.flag_6c && state.flag_74 && state.flag_7c && state.flag_90);
    reset_override_flags_block(state,0);
    expect(!state.yaw_enabled && !state.pitch_enabled && !state.flag_6c && !state.flag_74 && !state.flag_7c && !state.flag_90 && state.yaw==99 && state.pitch==88);
    expect(!consume_hidden_yaw_block(state));
    expect(!consume_hidden_pitch_block(state,output) && std::signbit(output));
    state.yaw_enabled=0xff;expect(consume_hidden_yaw_block(state)==99 && state.yaw_enabled==0);
    state.pitch_enabled=7;expect(consume_hidden_pitch_block(state,output) && output==88 && state.pitch_enabled==0);
    std::cout<<"{\"passed\":true,\"semantic_checks\":"<<checks
        <<",\"model\":\"analyst-authored hidden-angle consumer/reset blocks\","
        "\"target_runtime_executed\":false,\"whole_update_lifecycle_recovered\":false}\n";
}
