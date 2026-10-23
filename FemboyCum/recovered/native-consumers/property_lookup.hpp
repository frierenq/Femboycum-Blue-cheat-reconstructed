#pragma once
#include <cstdint>
#include <vector>

// Analyst-authored semantic model of original 0x41b89240 / 0x41b89800.
// These ordinary C++ containers do not reproduce the native memory ABI.
// Numeric keys are supplied; their original string-hash algorithm is unresolved.
namespace femboylose::recovered {
struct PropertyDescriptor {
    std::uint32_t offset; // Native descriptor +0x2c.
};
struct PropertyPair {
    std::uint32_t key;
    const PropertyDescriptor* descriptor;
};
struct PropertyNode {
    std::uint32_t table_key=0;                 // Native node +0.
    const PropertyDescriptor* descriptor=nullptr; // Native node +4.
    std::uint32_t property_key=0;              // Native node +8.
    std::uint32_t base_offset=0;               // Native node +0xc.
    std::vector<PropertyPair> properties;      // Native +0x10/+0x14, stride 8.
    std::vector<PropertyNode> children;        // Native +0x1c/+0x20, stride 0x2c.
};
inline std::uint32_t find_property_in_node(const PropertyNode& node,std::uint32_t key,
                                          const PropertyDescriptor** result=nullptr){
    for(const auto& pair:node.properties){
        if(pair.key==key){
            if(result)*result=pair.descriptor;
            return pair.descriptor->offset+node.base_offset;
        }
    }
    for(const auto& child:node.children){
        if(child.property_key==key){
            if(result)*result=child.descriptor;
            return child.base_offset+node.base_offset;
        }
        const auto offset=find_property_in_node(child,key,result);
        if(offset!=0)return offset+node.base_offset;
    }
    return 0;
}
inline std::uint32_t find_property(const std::vector<PropertyNode>& tables,
                                   std::uint32_t table_key,std::uint32_t property_key,
                                   const PropertyDescriptor** result=nullptr){
    for(const auto& table:tables){
        if(table.table_key==table_key){
            const auto offset=find_property_in_node(table,property_key,result);
            if(offset!=0)return offset;
        }
    }
    return 0;
}
}
