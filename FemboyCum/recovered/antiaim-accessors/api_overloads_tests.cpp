#include "api_overloads.hpp"
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
    constexpr std::uint32_t wanted[3][2]{{0x41a2d810u,0x419f4f40u},
        {0x41958980u,0x4199b590u},{0x419c8400u,0x419d41d0u}};
    for(unsigned row=0;row<3;++row){
        const auto method=static_cast<AntiaimMethod>(row);
        expect(select_antiaim_overload(method,true,1,0)==wanted[row][0]);
        expect(select_antiaim_overload(method,true,2,1)==wanted[row][1]);
        expect(!select_antiaim_overload(method,true,2,3));
        expect(!select_antiaim_overload(method,true,2,0));
        expect(!select_antiaim_overload(method,true,0,0));
        expect(!select_antiaim_overload(method,true,3,1));
        expect(!select_antiaim_overload(method,false,1,0));
    }
    InverterRequestState request{1,42,1};
    record_inverter_request(request,0,1,77,20,30);
    expect(request.active==1 && request.request_counter==77 && request.request_value==0);
    request.active=0;
    record_inverter_request(request,1,0,77,20,30);
    expect(request.active==0 && request.request_counter==51 && request.request_value==1);
    request.active=1;
    record_inverter_request(request,0x7f,0,77,0xffffffffu,0);
    expect(request.active==1 && request.request_counter==0 && request.request_value==0x7f);
    expect(rotation_boolean_form(0,725,-540)==5);
    expect(rotation_boolean_form(1,725,-540)==-180);
    expect(rotation_boolean_form(0xff,725,-540)==-180);
    const auto nan=std::numeric_limits<float>::quiet_NaN();
    expect(rotation_boolean_form(0,725,nan)==5);
    expect(rotation_boolean_form(1,725,nan)==0);
    expect(std::signbit(rotation_boolean_form(1,725,-360)));
    std::cout<<"{\"passed\":true,\"semantic_checks\":"<<checks
        <<",\"model\":\"analyst-authored overload/request/rotation slices\","
        "\"target_runtime_executed\":false,\"pending_request_consumption_recovered\":false}\n";
}
