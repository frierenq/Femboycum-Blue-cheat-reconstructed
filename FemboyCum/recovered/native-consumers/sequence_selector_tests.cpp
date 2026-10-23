#include "sequence_selector.hpp"
#include <cmath>
#include <iostream>
#include <limits>
#include <stdexcept>
using namespace femboylose::recovered;
int main(){
    unsigned checks=0;
    const auto require=[&](bool okay,const char* why){if(!okay)throw std::runtime_error(why);++checks;};
    SequenceCaches fixture{};
    for(unsigned row=0;row<5;++row)for(unsigned col=0;col<4;++col)
        fixture[row][col]=1000+static_cast<int>(row)*10+static_cast<int>(col);
    // These are authored fixtures, not original runtime sequence numbers.
    struct Case{float duck,speed;unsigned variant;};
    const std::array<Case,4> cases{{{0,0,0},{0,1,1},{1,0,2},{1,1,3}}};
    const std::array<std::uint32_t,5> native_rows{
        0x4223f430u,0x4223f418u,0x4223f2f8u,0x4223f370u,0x4223f380u};
    for(unsigned row=0;row<5;++row)for(const auto& c:cases){
        const auto chosen=select_cached_sequence(985+static_cast<int>(row),c.duck,c.speed,fixture);
        require(chosen && chosen->sequence==1000+static_cast<int>(row)*10+static_cast<int>(c.variant)
                && chosen->variant==c.variant && chosen->cache_address==native_rows[row]+4u*c.variant,
                "independent decision matrix and native address table");
    }
    auto chosen=select_cached_sequence(985,0.55f,0.25f,fixture);
    require(chosen && chosen->variant==0,"both exact thresholds select the low branch");
    chosen=select_cached_sequence(985,std::nextafter(0.55f,1.0f),0.25f,fixture);
    require(chosen && chosen->variant==2,"next float above duck threshold selects high duck");
    chosen=select_cached_sequence(985,0.55f,std::nextafter(0.25f,1.0f),fixture);
    require(chosen && chosen->variant==1,"next float above speed threshold selects fast branch");
    chosen=select_cached_sequence(985,-2,-4,fixture);
    require(chosen && chosen->variant==0,"slice has no lower clamp on input floats");
    const float nan=std::numeric_limits<float>::quiet_NaN();
    chosen=select_cached_sequence(985,nan,1,fixture);require(chosen && chosen->variant==1,"unordered duck comparison selects low duck");
    chosen=select_cached_sequence(985,1,nan,fixture);require(chosen && chosen->variant==2,"unordered speed comparison selects slow");
    chosen=select_cached_sequence(985,nan,nan,fixture);require(chosen && chosen->variant==0,"both unordered comparisons select first variant");
    require(!select_cached_sequence(984,1,1,fixture),"selector below table is rejected");
    require(!select_cached_sequence(990,1,1,fixture),"selector above table is rejected");
    require(!select_cached_sequence(std::numeric_limits<int>::min(),1,1,fixture),"minimum signed selector uses defined unsigned range check");
    require(!select_cached_sequence(std::numeric_limits<int>::max(),1,1,fixture),"maximum signed selector uses defined unsigned range check");
    fixture[0][0]=0;require(!select_cached_sequence(985,0,0,fixture),"zero cached sequence produces no selected result");
    fixture[0][2]=-1;require(!select_cached_sequence(985,1,0,fixture),"negative cached sequence produces no selected result");
    chosen=select_cached_sequence(985,1,1,fixture);require(chosen && chosen->sequence==1003,"invalid other cache slots do not suppress chosen positive entry");
    std::cout<<"{\"passed\":true,\"semantic_checks\":"<<checks<<",\"target_code_executed\":false,\"scope\":\"original selector slice; authored cache fixtures\"}\n";
}
