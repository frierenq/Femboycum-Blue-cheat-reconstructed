#include "turn16_quantization.hpp"
#include "api_overloads.hpp"
#include <array>
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
    // The standalone model does not change the caller's FP control settings.
    expect((_mm_getcsr()&0x7f80u)==0x1f80u);
    constexpr float unit=45.0f/8192.0f;
    struct Case{float input;std::uint16_t code;};
    const std::array<Case,19> cases{{
        {0,0},{-0.0f,0},{1,182},{-1,65354},{0.25f,45},{-0.25f,65491},
        {90,16384},{-90,49152},{180,32768},{-180,32768},{360,0},{-360,0},
        {720,0},{-720,0},{359.999f,65535},{360.001f,0},
        {11796479.0f,65408},{-11796479.0f,128},{11796480.0f,0}
    }};
    for(const auto& sample:cases){
        expect(turn16_code(sample.input)==sample.code);
        expect(quantize_turn16(sample.input)==static_cast<float>(sample.code)*unit);
    }
    for(const float value:{std::numeric_limits<float>::quiet_NaN(),std::numeric_limits<float>::infinity(),
        -std::numeric_limits<float>::infinity(),std::numeric_limits<float>::max(),
        -std::numeric_limits<float>::max(),std::numeric_limits<float>::denorm_min(),
        -std::numeric_limits<float>::denorm_min(),-11796480.0f}){
        const auto result=quantize_turn16(value);expect(result==0 && !std::signbit(result));
    }
    expect(quantize_turn16(-0.0f)==0 && !std::signbit(quantize_turn16(-0.0f)));
    expect(turn16_code(unit)==1 && turn16_code(-unit)==65535);
    expect(turn16_code(std::nextafter(unit,0.0f))==0);
    expect(turn16_code(-std::nextafter(unit,0.0f))==0);
    const float rounded_boundary=std::nextafter(5.0f*unit,0.0f);
    expect(turn16_code(rounded_boundary)==5);
    expect(static_cast<int>(static_cast<double>(rounded_boundary)*(65536.0/360.0))==4);
    // All representable output codes survive a re-quantization without drift.
    bool all_codes_roundtrip=true;
    for(std::uint32_t code=0;code<65536u;++code){
        const float angle=static_cast<float>(code)*unit;
        if(turn16_code(angle)!=code || quantize_turn16(angle)!=angle){all_codes_roundtrip=false;break;}
    }
    expect(all_codes_roundtrip);
    // Numeric composition with the recovered alternate-accessor transformation.
    // These fixtures do not assert that the enclosing native writer was reached.
    expect(rotation_boolean_form(1,999,quantize_turn16(-1))==-0.999755859375f);
    expect(rotation_boolean_form(1,999,quantize_turn16(-180))==180);
    expect(rotation_boolean_form(1,999,quantize_turn16(1))==0.999755859375f);
    expect(rotation_boolean_form(0,181,quantize_turn16(-1))==-179);
    std::cout<<"{\"passed\":true,\"semantic_checks\":"<<checks
        <<",\"quantized_codes_checked\":65536,\"model\":\"analyst-authored SSE turn16 quantization\","
        "\"target_runtime_executed\":false,\"whole_rotation_writer_recovered\":false}\n";
}
