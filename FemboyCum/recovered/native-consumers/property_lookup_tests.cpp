#include "property_lookup.hpp"
#include "layer_predicate.hpp"
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
    constexpr std::uint32_t table_key=101,property_key=202;
    PropertyDescriptor first{20},second{40},zero{0},other{999};
    const PropertyDescriptor* output=&other;
    expect(find_property({},table_key,property_key,&output)==0 && output==&other);
    PropertyNode root;root.table_key=table_key;root.base_offset=10;
    root.properties={{property_key,&first},{property_key,&second}};
    expect(find_property({root},table_key,property_key,&output)==30 && output==&first);
    expect(find_property({root},table_key,property_key)==30);
    output=&other;
    expect(find_property({root},999,property_key,&output)==0 && output==&other);
    expect(find_property({root},table_key,999,&output)==0 && output==&other);
    PropertyNode child;child.property_key=property_key;child.base_offset=7;child.descriptor=&second;
    root.children={child};
    expect(find_property({root},table_key,property_key,&output)==30 && output==&first);
    root.properties.clear();
    expect(find_property({root},table_key,property_key,&output)==17 && output==&second);
    child.property_key=303;child.base_offset=30;child.properties={{property_key,&first}};
    root.children={child};
    expect(find_property({root},table_key,property_key,&output)==60 && output==&first);
    PropertyNode zero_child;zero_child.property_key=303;zero_child.properties={{property_key,&zero}};
    root.children={zero_child,child};
    expect(find_property({root},table_key,property_key,&output)==60 && output==&first);
    root.children={zero_child};output=&other;
    expect(find_property({root},table_key,property_key,&output)==0 && output==&zero);
    root.base_offset=0;root.properties={{property_key,&zero}};root.children={child};
    expect(find_property({root},table_key,property_key,&output)==0 && output==&zero);
    PropertyNode later;later.table_key=table_key;later.properties={{property_key,&second}};
    expect(find_property({root,later},table_key,property_key,&output)==40 && output==&second);
    child.property_key=property_key;child.base_offset=0;child.descriptor=&first;
    root.properties.clear();root.children={child,later};
    expect(find_property_in_node(root,property_key,&output)==0 && output==&first);
    root.base_offset=0xfffffff0u;root.children.clear();root.properties={{property_key,&first}};
    expect(find_property({root},table_key,property_key)==4);
    root.base_offset=0xfffffff0u;child.property_key=303;child.base_offset=0;
    PropertyDescriptor sixteen{16};child.properties={{property_key,&sixteen}};root.properties.clear();root.children={child};
    expect(find_property({root},table_key,property_key,&output)==0 && output==&sixteen);

    const float nan=std::numeric_limits<float>::quiet_NaN();
    const float inf=std::numeric_limits<float>::infinity();
    expect(layer_nine_predicate(true,0.5f,1.0f));
    expect(!layer_nine_predicate(false,0.5f,1.0f));
    expect(!layer_nine_predicate(true,1.0f,1.0f));
    expect(!layer_nine_predicate(true,2.0f,1.0f));
    expect(layer_nine_predicate(true,-0.5f,1.0f));
    expect(!layer_nine_predicate(true,nan,1.0f));
    expect(!layer_nine_predicate(true,0.5f,nan));
    expect(!layer_nine_predicate(true,0.5f,0.0f));
    expect(!layer_nine_predicate(true,0.5f,-0.0f));
    expect(layer_nine_predicate(true,0.5f,-1.0f));
    expect(layer_nine_predicate(true,-inf,inf));
    expect(!layer_nine_predicate(true,inf,1.0f));
    expect(!cached_property_fallback(200.0f));
    expect(!cached_property_fallback(199.0f));
    expect(cached_property_fallback(201.0f));
    expect(cached_property_fallback(nan));
    expect(cached_property_fallback(inf));
    expect(!cached_property_fallback(-inf));
    std::cout<<"{\"passed\":true,\"semantic_checks\":"<<checks
        <<",\"model\":\"analyst-authored property lookup and layer predicate blocks\","
        "\"target_runtime_executed\":false,\"hash_algorithm_recovered\":false}\n";
}
