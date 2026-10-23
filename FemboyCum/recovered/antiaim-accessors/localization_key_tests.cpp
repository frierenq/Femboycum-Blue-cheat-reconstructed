#include "body_yaw_configuration.hpp"
#include <array>
#include <cstdlib>
#include <iostream>
using namespace femboylose::recovered;
static unsigned checks=0;
static void expect(bool condition){
    ++checks;
    if(!condition){std::cerr<<"failed check "<<checks<<'\n';std::exit(1);}
}
int main(){
    expect(localization_key("")==5381u);
    expect(localization_key("a")==177670u);
    expect(localization_key("A")==177638u);
    expect(localization_key(std::string_view("a\0b",3))==193482728u);
    expect(localization_key(std::string_view("\x80",1))==177445u);
    expect(localization_key(std::string_view("\xff",1))==177572u);
    expect(localization_key(std::string_view("\xc3\xa9",2))==5857809u);
    expect(localization_key("abcdefg")==0x1a623b21u);
    expect(localization_key("abcdefgh")==0x66a99fa9u);
    expect(localization_key("abcdefghi")==0x3bdd9532u);
    expect(localization_key("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")==0x9c86aa44u);
    struct NativeJoin{std::string_view key;std::uint32_t identifier;};
    const std::array<NativeJoin,14> joins{{
        {"anti_aim_angles_body_yaw_inverter",0x7ee0a3ebu},
        {"anti_aim_angles_body_yaw_inverter_tooltip",0x21e357f5u},
        {"anti_aim_angles_body_yaw_options",0x2b934928u},
        {"anti_aim_angles_body_yaw_options_avoid_overlap",0x16049072u},
        {"anti_aim_angles_body_yaw_options_jitter",0x47fd6e39u},
        {"anti_aim_angles_body_yaw_options_randomize_jitter",0xddda9401u},
        {"anti_aim_angles_body_yaw_options_anti_bruteforce",0xa2b92dc3u},
        {"anti_aim_angles_body_yaw_freestanding",0xa5d92e96u},
        {"anti_aim_angles_body_yaw_freestanding_tooltip",0xa4e55da0u},
        {"anti_aim_angles_body_yaw_freestanding_peek_fake",0x6195cf50u},
        {"anti_aim_angles_body_yaw_freestanding_peek_real",0x619c739du},
        {"anti_aim_angles_freestanding_body_freestanding",0xd1a0889fu},
        {"anti_aim_angles",0xd74c30c0u},{"menu_off",0x7b878bd4u}
    }};
    for(const auto& join:joins)expect(localization_key(join.key)==join.identifier);
    std::cout<<"{\"passed\":true,\"semantic_checks\":"<<checks
        <<",\"model\":\"analyst-authored signed-byte localization key hash\","
        "\"target_runtime_executed\":false,\"whole_configuration_runtime_recovered\":false}\n";
}
