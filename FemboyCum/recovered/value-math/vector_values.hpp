#pragma once
#include <cmath>
#include <limits>

// Analyst-authored semantic reconstruction from the FemboyLose embedded core.
// This is standalone value math, not recovered original source or a Lua ABI.
// Finite-input arithmetic only; ambient SSE flags and NaN payloads are unmodeled.
namespace femboylose::recovered {
struct Vec3 { float x, y, z; };

inline float length_squared(Vec3 v) { // 0x4176abc0
    return v.z*v.z + (v.x*v.x + v.y*v.y);
}
inline float length(Vec3 v) { return std::sqrt(length_squared(v)); } // 0x4174cfb0
inline float length_2d_squared(Vec3 v) { return v.y*v.y + v.x*v.x; } // 0x41766d10
inline float length_2d(Vec3 v) { return std::sqrt(length_2d_squared(v)); } // 0x417437d0
inline float dot(Vec3 a, Vec3 b) { // 0x417728e0
    return b.z*a.z + (b.x*a.x + b.y*a.y);
}
inline Vec3 cross(Vec3 a, Vec3 b) { // 0x41772a00
    return {b.z*a.y - a.z*b.y, b.x*a.z - a.x*b.z, a.x*b.y - b.x*a.y};
}
inline float normalize(Vec3& v) { // 0x41767560
    const float magnitude=std::sqrt((v.y*v.y + v.x*v.x) + v.z*v.z);
    const float factor=1.0f/(std::numeric_limits<float>::epsilon()+magnitude);
    v={factor*v.x,factor*v.y,factor*v.z};
    return magnitude;
}
inline Vec3 normalized(Vec3 v) { normalize(v);return v; } // 0x41742050

inline float dist_to_ray(Vec3 point,Vec3 origin,Vec3 direction) { // 0x41754a10
    const Vec3 d{point.x-origin.x,point.y-origin.y,point.z-origin.z};
    const float cx=direction.y*d.z-d.y*direction.z;
    const float cy=direction.z*d.x-d.z*direction.x;
    const float cz=direction.x*d.y-d.x*direction.y;
    // The original leaf does not divide by |direction| or clamp endpoints.
    return std::sqrt(cz*cz + (cx*cx + cy*cy));
}

struct SegmentProjection {
    Vec3 closest;
    float along;
    float signed_distance;
};
inline SegmentProjection project_segment(Vec3 point,Vec3 begin,Vec3 end) { // 0x417784e0
    const Vec3 delta{end.x-begin.x,end.y-begin.y,end.z-begin.z};
    const float span=std::sqrt(delta.y*delta.y + (delta.z*delta.z + delta.x*delta.x));
    const float inverse=1.0f/(span!=0.0f?span:1.0f);
    const Vec3 unit{inverse*delta.x,inverse*delta.y,inverse*delta.z};
    const Vec3 from{point.x-begin.x,point.y-begin.y,point.z-begin.z};
    const float along=(from.z*unit.z + from.x*unit.x) + from.y*unit.y;
    if(along<0.0f || along>span){
        const Vec3 closest=along<0.0f?begin:end;
        const Vec3 d{point.x-closest.x,point.y-closest.y,point.z-closest.z};
        return {closest,along,-std::sqrt((d.y*d.y+d.z*d.z)+d.x*d.x)};
    }
    const Vec3 closest{begin.x+along*unit.x,begin.y+along*unit.y,begin.z+along*unit.z};
    const Vec3 d{point.x-closest.x,point.y-closest.y,point.z-closest.z};
    return {closest,along,std::sqrt(d.y*d.y+(d.z*d.z+d.x*d.x))};
}
inline Vec3 closest_ray_point(Vec3 point,Vec3 begin,Vec3 end) {
    // 0x4175ff90 requests the point output from 0x417784e0, discarding distance.
    return project_segment(point,begin,end).closest;
}
}
