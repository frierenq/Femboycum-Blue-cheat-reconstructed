#include "rotation_math.hpp"
#include <cstdlib>
#include <iostream>
#include <limits>
using namespace femboylose::recovered;
static unsigned checks=0;
static void expect(bool condition){
    ++checks;
    if(!condition){std::cerr<<"failed check "<<checks<<'\n';std::exit(1);}
}
static float from_bits(std::uint32_t bits){float value;std::memcpy(&value,&bits,4);return value;}
static std::uint32_t bits(float value){std::uint32_t out;std::memcpy(&out,&value,4);return out;}
static void value_case(float input,float wanted){expect(bits(normalized_rotation(input))==bits(wanted));}
int main(){
    value_case(0.0f,0.0f);value_case(-0.0f,-0.0f);
    value_case(1.0f,1.0f);value_case(-1.0f,-1.0f);
    value_case(180.0f,180.0f);value_case(-180.0f,-180.0f);
    value_case(181.0f,-179.0f);value_case(-181.0f,179.0f);
    value_case(359.0f,-1.0f);value_case(-359.0f,1.0f);
    value_case(360.0f,0.0f);value_case(-360.0f,-0.0f);
    value_case(540.0f,180.0f);value_case(-540.0f,-180.0f);
    value_case(720.0f,0.0f);value_case(-720.0f,-0.0f);
    value_case(900.0f,180.0f);value_case(-900.0f,-180.0f);
    expect(bits(normalized_rotation(from_bits(0x43340001u)))==0xc333ffffu);
    expect(bits(normalized_rotation(from_bits(0xc3340001u)))==0x4333ffffu);
    expect(bits(normalized_rotation(from_bits(0x43b3ffffu)))==0xb8000000u);
    expect(bits(normalized_rotation(from_bits(0xc3b3ffffu)))==0x38000000u);
    value_case(from_bits(1),from_bits(1));
    value_case(from_bits(0x80000001u),from_bits(0x80000001u));
    value_case(std::numeric_limits<float>::max(),0.0f);
    value_case(-std::numeric_limits<float>::max(),-0.0f);
    value_case(from_bits(0x7fc1abcdu),0.0f);
    value_case(from_bits(0xffc1abcdu),0.0f);
    value_case(std::numeric_limits<float>::infinity(),0.0f);
    value_case(-std::numeric_limits<float>::infinity(),0.0f);
    expect(classify_rotation_input(0)==0);
    expect(classify_rotation_input(-0.0f)==0);
    expect(classify_rotation_input(1)==-1);
    expect(classify_rotation_input(from_bits(1))==-2);
    expect(classify_rotation_input(std::numeric_limits<float>::infinity())==1);
    expect(classify_rotation_input(from_bits(0x7fc1abcdu))==2);
    std::cout<<"{\"passed\":true,\"semantic_checks\":"<<checks
        <<",\"model\":\"analyst-authored two-pass rotation transformation\","
        "\"target_runtime_executed\":false,\"original_fpu_environment_reimplemented\":false}\n";
}
