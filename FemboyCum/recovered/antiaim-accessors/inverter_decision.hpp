#pragma once
#include "rotation_math.hpp"
#include "body_yaw_configuration.hpp"
#include <limits>

// Analyst-authored reconstruction of the local 0x41360e20 decision tree.
// Addresses below are integer keys passed to a supplied data provider. This
// code never dereferences them or accesses an original module/process.
// External RandomSeed/RandomInt behavior is supplied, not reimplemented here.
namespace femboylose::recovered {
struct InverterDecisionData {
    virtual ~InverterDecisionData()=default;
    virtual std::uint8_t byte(std::uint32_t address)=0;
    virtual std::uint32_t word(std::uint32_t address)=0;
    virtual void random_seed(std::uint32_t seed)=0;
    virtual std::int32_t random_int(std::int32_t low,std::int32_t high)=0;
};
enum class InverterDecisionRoute {
    MatchingRequest,PerEntity,SmallState,MinusMetric,PlusMetric,
    SignedParity,ExternalRandom,LateRequest,ConfiguredDefault
};
struct InverterDecisionResult {
    float value;
    InverterDecisionRoute route; // Analyst instrumentation, not a native result.
};
inline float decision_float(InverterDecisionData& data,std::uint32_t address){
    const auto bits=data.word(address);float result;
    std::memcpy(&result,&bits,sizeof(result));return result;
}
inline std::int32_t decision_signed(std::uint32_t word){
    std::int32_t result;std::memcpy(&result,&word,sizeof(result));return result;
}
inline float wrapped_angle_difference(float first,float second){
    // Original 0x41573c40 normalizes each operand before subtracting, then
    // normalizes the float subtraction. Normalizing only the difference differs.
    const float a=normalize_rotation_pass(first);
    const float b=normalize_rotation_pass(second);
    const float difference=a-b;
    return normalize_rotation_pass(difference);
}
inline std::uint8_t selected_decision_byte(InverterDecisionData& data,
    std::uint32_t config,std::uint32_t high_offset){
    const auto selector=data.byte(config+high_offset+1u);
    return data.byte(config+high_offset-static_cast<std::uint32_t>(selector==0));
}
struct DecisionModeSelection {
    std::uint32_t config;
    std::uint32_t bits;
};
inline DecisionModeSelection decision_mode(InverterDecisionData& data){
    const auto config=data.word(0x424f639cu);
    const auto selector=data.byte(config+0x16e9cu);
    const auto first=data.word(config+0x16e94u);
    const auto second=data.word(config+0x16e98u);
    return {config,selector?second:first};
}
inline float request_sign(std::uint8_t value){return value?-60.0f:60.0f;}
inline InverterDecisionResult inverter_decision(InverterDecisionData& data,
    std::uint32_t context,float input_angle){
    using Route=InverterDecisionRoute;
    const auto request_counter=data.word(context+0x40u);
    const auto counter=data.word(0x424f4b18u);
    if(request_counter==counter)return {request_sign(data.byte(context+0x44u)),Route::MatchingRequest};
    auto mode=decision_mode(data);
    if((mode.bits&option_bit(BodyYawOption::AntiBruteforce))!=0 && data.byte(0x424b1c9du)!=0){
        const auto index=decision_signed(data.word(0x4223bef4u));
        if(index>0){
            // The original local branch supplies no upper-bound check.
            const auto entry=data.word(context+0x1a4u+static_cast<std::uint32_t>(index)*4u);
            if(entry!=0)return {entry==1u?-60.0f:60.0f,Route::PerEntity};
        }
    }
    bool special=false;
    if(selected_decision_byte(data,mode.config,0x17285u)!=0 &&
       selected_decision_byte(data,mode.config,0x170a5u)!=0){
        const float stored=decision_float(data,context+4u);
        // UCOMISS/SETNE is false for unordered, unlike C++ NaN != sentinel.
        special=!std::isnan(stored) && stored!=std::numeric_limits<float>::max();
    }
    const auto option_index=data.byte(mode.config+0x16fa4u);
    const auto option=decision_signed(data.word(mode.config+0x16f9cu+static_cast<std::uint32_t>(option_index)*4u));
    if(option>0 || special){
        const auto state=data.word(context);
        if(state<=1u){
            const float base=state==0u?60.0f:-60.0f;
            return {special || option!=static_cast<std::int32_t>(BodyYawFreestandingMode::PeekReal)?-base:base,Route::SmallState};
        }
    }
    if((mode.bits&option_bit(BodyYawOption::AvoidOverlap))!=0){
        const float angle=normalize_rotation_pass(input_angle);
        const float minus_reference=decision_float(data,context+0x20u);
        const float minus_angle=angle-decision_float(data,context+0x14u);
        const float minus_metric=std::fabs(wrapped_angle_difference(minus_angle,minus_reference));
        const float plus_reference=decision_float(data,context+0x20u);
        const float plus_angle=angle+decision_float(data,context+0x14u);
        const float plus_metric=std::fabs(wrapped_angle_difference(plus_angle,plus_reference));
        const float twice_plus=plus_metric+plus_metric;
        if(minus_metric>twice_plus)return {60.0f,Route::MinusMetric};
        const float twice_minus=minus_metric+minus_metric;
        if(plus_metric>twice_minus)return {-60.0f,Route::PlusMetric};
        // Original 0x413610d8 re-reads the global and both mode words here.
        mode=decision_mode(data);
    }
    if((mode.bits&option_bit(BodyYawOption::Jitter))!=0){
        if((mode.bits&option_bit(BodyYawOption::RandomizeJitter))!=0){
            const auto engine=data.word(0x4223f428u);
            data.random_seed(data.word(engine+0x4d2cu));
            const auto result=data.random_int(0,1);
            return {result==0?60.0f:-60.0f,Route::ExternalRandom};
        }
        const bool positive_odd=(data.word(context+0x10u)&0x80000001u)==1u;
        return {positive_odd?60.0f:-60.0f,Route::SignedParity};
    }
    const auto late_request=data.word(context+0x40u);
    const auto late_counter=data.word(0x424f4b18u);
    if(late_request==late_counter)return {request_sign(data.byte(context+0x44u)),Route::LateRequest};
    return {request_sign(selected_decision_byte(data,mode.config,0x16b75u)),Route::ConfiguredDefault};
}
}
