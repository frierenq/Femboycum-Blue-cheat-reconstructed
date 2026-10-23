#include "vector_values.hpp"
#include <iostream>
#include <stdexcept>
using namespace femboylose::recovered;
int main(){
    unsigned checks=0;
    const auto require=[&](bool ok,const char* why){if(!ok)throw std::runtime_error(why);++checks;};
    const auto near=[](float a,float b){return std::fabs(a-b)<=0.000005f;};
    const auto same=[&](Vec3 a,Vec3 b){return near(a.x,b.x)&&near(a.y,b.y)&&near(a.z,b.z);};
    require(length_squared({3,4,12})==169 && length({3,4,12})==13,"three-dimensional length");
    require(length_2d_squared({3,4,120})==25 && length_2d({3,4,120})==5,"2D variants ignore z");
    require(length({0,0,0})==0,"zero length");
    require(dot({1,2,3},{-2,1,4})==12,"dot with mixed signs");
    require(same(cross({1,0,0},{0,1,0}),{0,0,1}),"cross-product handedness");
    require(same(cross({0,1,0},{1,0,0}),{0,0,-1}),"cross-product antisymmetry");
    const Vec3 c=cross({2,-3,4},{-1,5,2});
    require(dot(c,{2,-3,4})==0 && dot(c,{-1,5,2})==0,"cross product orthogonal to both inputs");
    Vec3 v{3,4,12};require(normalize(v)==13 && near(length(v),1),"in-place normalize returns previous magnitude");
    Vec3 unit{1,0,0};normalize(unit);
    require(unit.x<1 && unit.x>0.999999f,"epsilon leaves a unit vector slightly shorter");
    Vec3 zero{0,-0.0f,0};require(normalize(zero)==0 && zero.x==0 && std::signbit(zero.y),"zero normalization remains finite and retains negative zero");
    const float epsilon=std::numeric_limits<float>::epsilon();Vec3 tiny{epsilon,0,0};
    require(normalize(tiny)==epsilon && tiny.x==0.5f,"epsilon-size input is not normalized to unit length");
    const Vec3 source{0,3,4};const Vec3 copy=normalized(source);
    require(same(source,{0,3,4}) && near(length(copy),1),"normalized returns a value without modifying input");
    require(dist_to_ray({4,3,0},{0,0,0},{1,0,0})==3,"unit direction produces perpendicular distance");
    require(dist_to_ray({4,3,0},{0,0,0},{2,0,0})==6,"direction magnitude scales native dist_to_ray result");
    require(dist_to_ray({-4,3,0},{0,0,0},{1,0,0})==3,"native dist_to_ray has no endpoint clamp");
    require(dist_to_ray({400,300,200},{0,0,0},{0,0,0})==0,"zero direction returns zero despite point separation");
    auto p=project_segment({4,3,0},{0,0,0},{10,0,0});
    require(same(p.closest,{4,0,0}) && p.along==4 && p.signed_distance==3,"interior projection");
    p=project_segment({-2,3,0},{0,0,0},{10,0,0});
    require(same(p.closest,{0,0,0}) && p.along==-2 && near(p.signed_distance,-std::sqrt(13.0f)),"before begin gives signed negative distance and endpoint");
    p=project_segment({12,3,0},{0,0,0},{10,0,0});
    require(same(p.closest,{10,0,0}) && p.along==12 && near(p.signed_distance,-std::sqrt(13.0f)),"after end gives signed negative distance and endpoint");
    p=project_segment({0,3,0},{0,0,0},{10,0,0});
    require(p.signed_distance==3,"projection exactly at begin uses interior sign");
    p=project_segment({10,3,0},{0,0,0},{10,0,0});
    require(p.signed_distance==3,"projection exactly at end uses interior sign");
    p=project_segment({4,6,3},{1,2,3},{1,2,3});
    require(same(p.closest,{1,2,3}) && p.along==0 && p.signed_distance==5,"degenerate segment uses denominator one and remains finite");
    p=project_segment({4,3,0},{10,0,0},{0,0,0});
    require(same(p.closest,{4,0,0}) && p.along==6 && p.signed_distance==3,"reversing segment preserves closest point");
    require(same(closest_ray_point({14,3,0},{0,0,0},{10,0,0}),{10,0,0}),"closest_ray_point clamps beyond end despite ray name");
    require(same(closest_ray_point({14,3,0},{10,0,0},{20,0,0}),{14,0,0}),"projection respects translated segment");
    require(same(closest_ray_point({2,1,8},{2,1,0},{2,1,10}),{2,1,8}),"non-x-axis segment");
    require(dist_to_ray({4,3,0},{0,0,0},{-1,0,0})==3,"reversing direction preserves cross magnitude");
    std::cout<<"{\"passed\":true,\"semantic_checks\":"<<checks<<",\"target_code_executed\":false,\"scope\":\"finite standalone vector math; no Lua ABI\"}\n";
}
