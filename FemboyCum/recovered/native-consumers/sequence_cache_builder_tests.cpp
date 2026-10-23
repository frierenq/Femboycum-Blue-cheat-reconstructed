#include "sequence_cache_builder.hpp"
#include "sequence_selector.hpp"
#include <cstdlib>
#include <iostream>
#include <vector>
using namespace femboylose::recovered;
static unsigned checks=0;
static void expect(bool condition){
    ++checks;
    if(!condition){std::cerr<<"check failed: "<<checks<<'\n';std::exit(1);}
}
struct Fixture {
    std::array<std::int32_t,5> answers;
    std::vector<std::string> calls;
    std::string base;
    std::int32_t operator()(const std::string& name){
        const std::array<std::string,5> names{{base,base+"_crouch",base+"_moving",
            base+"_crouch_moving",base+"_moving_crouch"}};
        calls.push_back(name);
        for(std::size_t i=0;i<names.size();++i)if(name==names[i])return answers[i];
        std::cerr<<"unexpected lookup: "<<name<<'\n';std::exit(1);
    }
};
static void scenario(std::array<std::int32_t,5> answers,
                     std::array<std::int32_t,4> wanted,unsigned lookup_count){
    Fixture fixture{answers,{},"jump"};
    expect(build_sequence_cache("jump",fixture)==wanted);
    const std::vector<std::string> ordered{"jump","jump_crouch","jump_moving",
        "jump_crouch_moving","jump_moving_crouch"};
    expect(fixture.calls==std::vector<std::string>(ordered.begin(),ordered.begin()+lookup_count));
}
int main(){
    SequenceCaches caches{};
    for(std::size_t row=0;row<sequence_cache_definitions.size();++row){
        const auto& definition=sequence_cache_definitions[row];
        const auto first=static_cast<std::int32_t>(100+10*row);
        Fixture fixture{{first,first+2,first+1,first+3,999},{},definition.base_name};
        caches[row]=build_sequence_cache(definition.base_name,fixture);
        expect(caches[row]==std::array<std::int32_t,4>{{first,first+1,first+2,first+3}});
        expect(fixture.calls==std::vector<std::string>{fixture.base,fixture.base+"_crouch",
            fixture.base+"_moving",fixture.base+"_crouch_moving"});
        for(unsigned variant=0;variant<4;++variant){
            const auto choice=select_cached_sequence(definition.selector,
                (variant&2u)?1.0f:0.0f,(variant&1u)?1.0f:0.0f,caches);
            expect(choice && choice->sequence==first+static_cast<std::int32_t>(variant)
                && choice->cache_address==definition.address+4u*variant);
        }
    }
    scenario({10,30,20,40,50},{10,20,30,40},4);
    scenario({10,-1,20,40,50},{10,20,10,40},4);
    scenario({10,30,-1,40,50},{10,10,30,40},4);
    scenario({10,-1,-1,40,50},{10,10,10,40},4);
    scenario({10,30,20,-1,50},{10,20,30,50},5);
    scenario({10,30,20,-1,-1},{10,20,30,20},5);
    scenario({-1,30,-1,-1,-1},{-1,-1,30,30},5);
    scenario({10,-1,-1,-1,-1},{10,10,10,10},5);
    scenario({-1,-1,-1,-1,-1},{-1,-1,-1,-1},5);
    scenario({10,0,-2,0,50},{10,-2,0,0},4);
    scenario({10,30,20,-2,50},{10,20,30,-2},4);
    scenario({10,30,20,-1,0},{10,20,30,0},5);
    scenario({10,30,20,-1,-2},{10,20,30,-2},5);
    std::cout<<"{\"passed\":true,\"semantic_checks\":"<<checks
        <<",\"model\":\"analyst-authored sequence-cache naming/fallback blocks\","
        "\"target_runtime_executed\":false,\"original_engine_callback_implemented\":false}\n";
}
