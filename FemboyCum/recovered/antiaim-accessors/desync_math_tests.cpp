#include "desync_math.hpp"
#include <cstdlib>
#include <iostream>
#include <limits>
using namespace femboylose::recovered;
static unsigned checks=0;
static void expect(bool condition){
    ++checks;
    if(!condition){std::cerr<<"failed check "<<checks<<'\n';std::exit(1);}
}
static std::uint32_t bits(float value){
    std::uint32_t result;std::memcpy(&result,&value,sizeof(result));return result;
}
struct Fixture {DesyncInputs input;std::uint32_t expected;};
int main(){
    // Authored finite fixtures, independently rounded after each binary32
    // stage of the recovered scalar formula. These are not runtime game data.
    const Fixture fixtures[]{
        {{0.0f,0.0f,0.0f,0.0f,60.0f},0x42700000u},
        {{0.0f,1.0f,0.0f,0.0f,60.0f},0x42400000u},
        {{1.0f,1.0f,0.0f,0.0f,60.0f},0x41f00000u},
        {{0.0f,1.0f,1.0f,0.5f,60.0f},0x421c0000u},
        {{0.0f,0.0f,1.0f,1.0f,60.0f},0x41f00000u},
        {{0.5f,0.75f,0.0f,0.0f,60.0f},0x42310000u},
        {{0.25f,0.75f,0.0f,0.0f,60.0f},0x423e8001u},
        {{0.0f,-1.0f,1.0f,0.0f,60.0f},0x42700000u},
        {{0.0f,2.0f,1.0f,0.0f,60.0f},0x42400000u},
        {{0.0f,0.0f,-1.0f,1.0f,60.0f},0x42700000u},
        {{0.0f,0.0f,2.0f,1.0f,60.0f},0x41f00000u},
        {{0.0f,0.0f,1.0f,2.0f,60.0f},0u},
        {{0.0f,0.0f,1.0f,3.0f,60.0f},0xc1f00000u},
        {{0.0f,0.0f,1.0f,-1.0f,60.0f},0x42700000u},
        {{0.0f,0.0f,1.0f,0.0f,-60.0f},0xc2700000u},
        {{0.0f,0.0f,1.0f,0.0f,0.0f},0u},
    };
    for(const auto& fixture:fixtures)expect(bits(maximum_desync_math(fixture.input))==fixture.expected);
    const float nan=std::numeric_limits<float>::quiet_NaN();
    const float inf=std::numeric_limits<float>::infinity();
    expect(maximum_desync_math({0,nan,0,0,60})==60);
    expect(maximum_desync_math({0,0,nan,1,60})==30);
    expect(maximum_desync_math({0,1,nan,0,60})==48);
    expect(std::isnan(maximum_desync_math({0,0,1,nan,60})));
    expect(std::isnan(maximum_desync_math({nan,nan,0,0,60})));
    expect(std::isnan(maximum_desync_math({0,0,0,0,nan})));
    expect(maximum_desync_math({0,inf,0,0,60})==48);
    expect(maximum_desync_math({0,-inf,0,0,60})==60);
    expect(maximum_desync_math({0,0,inf,1,60})==30);
    expect(maximum_desync_math({0,0,-inf,1,60})==60);
    expect(std::isnan(maximum_desync_math({inf,0,0,0,60})));
    expect(bits(binary32(0xbe4cccccu))==0xbe4cccccu);
    expect(bits(-0.2f)==0xbe4ccccdu);
    std::cout<<"{\"passed\":true,\"semantic_checks\":"<<checks
        <<",\"model\":\"analyst-authored original maximum-desync math leaf\","
        "\"target_runtime_executed\":false,\"full_public_api_recovered\":false}\n";
}
