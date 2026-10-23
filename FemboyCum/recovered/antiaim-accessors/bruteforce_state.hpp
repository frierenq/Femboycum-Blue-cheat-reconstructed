#pragma once
#include <array>
#include <cmath>
#include <cstdint>
#include <optional>
#include <emmintrin.h>

// Analyst-authored projections of two native state-update blocks. Addresses
// are supplied-data keys and are never dereferenced as process memory. Original
// event eligibility, entity callbacks and external RNG implementation are not
// replaced by these blocks.
namespace femboylose::recovered {
struct BruteforceStateData {
    virtual ~BruteforceStateData()=default;
    virtual std::uint32_t word(std::uint32_t address)=0;
    virtual void write_word(std::uint32_t address,std::uint32_t value)=0;
    virtual std::int32_t random_int(std::int32_t low,std::int32_t high)=0;
};
inline constexpr std::uint32_t bruteforce_context_global=0x42500648u;
inline constexpr std::uint32_t bruteforce_reference_offset=0xa0u;
inline constexpr std::uint32_t bruteforce_selected_offset=0x1a4u;
constexpr std::uint32_t bruteforce_slot(std::uint32_t context,std::uint32_t index,std::uint32_t offset){
    return context+index*4u+offset;
}
inline void hurt_state_update_block(BruteforceStateData& data,std::uint32_t entity_index){
    // Original 0x41571fb6..0x41572033; the index is the SECOND virtual index
    // result. Outer gates and the first index validation remain outside here.
    auto context=data.word(bruteforce_context_global);
    const auto reference=data.word(bruteforce_slot(context,entity_index,bruteforce_reference_offset));
    if(reference!=0){
        const std::uint32_t intermediate=reference==1u?2u:(reference==2u?1u:0u);
        data.write_word(bruteforce_slot(context,entity_index,bruteforce_selected_offset),intermediate);
        context=data.word(bruteforce_context_global);
    }
    const auto current=data.word(bruteforce_slot(context,entity_index,bruteforce_selected_offset));
    if(current==0){
        // This block calls RandomInt(1,2) without a local RandomSeed call.
        const auto next=static_cast<std::uint32_t>(data.random_int(1,2));
        context=data.word(bruteforce_context_global);
        data.write_word(bruteforce_slot(context,entity_index,bruteforce_selected_offset),next);
    }else{
        const std::uint32_t next=current==1u?2u:(current==2u?1u:0u);
        data.write_word(bruteforce_slot(context,entity_index,bruteforce_selected_offset),next);
    }
}
struct BruteforceTimingInputs {
    float stored_time;
    float counter_multiplier;
    std::int32_t counter;
};
inline void feedback_state_update_block(BruteforceStateData& data,std::uint32_t record_index,
    std::optional<BruteforceTimingInputs> timing){
    // Original null-result branch 0x415a7740 and numeric/update tail
    // 0x415a77d2..0x415a7844. This block assumes its outer gates were reached.
    bool use_reference=false;
    if(timing){
        const auto count=_mm_cvtsi32_ss(_mm_setzero_ps(),timing->counter);
        const auto clock=_mm_mul_ss(_mm_set_ss(timing->counter_multiplier),count);
        const auto difference=_mm_sub_ss(_mm_set_ss(timing->stored_time),clock);
        const auto magnitude=_mm_and_ps(difference,_mm_castsi128_ps(_mm_set1_epi32(0x7fffffff)));
        const float delta=_mm_cvtss_f32(magnitude);
        // UCOMISS/JAE: equality goes to selected; unordered falls to reference.
        use_reference=std::isnan(delta)||delta<0.25f;
    }
    const auto context=data.word(bruteforce_context_global);
    // Native record indices use +0xa4/+0x1a8; the consumer/hurt index convention
    // uses +0xa0/+0x1a4. These offsets correspond at record_index + 1.
    const auto offset=use_reference?bruteforce_reference_offset:bruteforce_selected_offset;
    const auto address=bruteforce_slot(context,record_index+1u,offset);
    const auto current=data.word(address);
    constexpr std::array<std::uint32_t,3> transitions{{1u,2u,1u}};
    data.write_word(address,current<=2u?transitions[current]:0u);
}
}
