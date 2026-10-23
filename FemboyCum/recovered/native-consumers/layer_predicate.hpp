#pragma once
#include <cmath>

// Analyst-authored reconstructions of original comparison blocks only.
// Callers provide already-read values; no native pointers or callbacks run.
namespace femboylose::recovered {
inline bool layer_nine_predicate(bool owner_present,float cycle,float weight){
    // UCOMISS 1.0,cycle + JBE rejects equal, greater and unordered cycle.
    // UCOMISS 0,weight + JNZ accepts ordered nonzero weight only.
    return owner_present && cycle<1.0f && !std::isnan(weight) && weight!=0.0f;
}
inline bool cached_property_fallback(float value){
    // UCOMISS 200.0,value + SETB includes the unordered case.
    return value>200.0f || std::isnan(value);
}
}
