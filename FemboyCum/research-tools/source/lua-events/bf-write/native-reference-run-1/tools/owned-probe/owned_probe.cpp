// Author-only expectation probe: links fc/bit_writer.cpp, never original bytes.
#include "fc/bit_writer.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <filesystem>
#include <cstdlib>
#include <memory>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <xmmintrin.h>

namespace {
using Bytes=std::array<std::uint8_t,20>;
struct MxcsrMode {
    unsigned prior=_mm_getcsr();
    MxcsrMode() { _mm_setcsr(0x1f80u); }
    ~MxcsrMode() { _mm_setcsr(prior); }
};
[[noreturn]] void fail(std::string value) { throw std::runtime_error(std::move(value)); }
void require(bool yes,std::string_view what) { if (!yes) fail(std::string(what)); }
int nibble(char c) {
    if (c>='0' && c<='9') return c-'0';
    if (c>='a' && c<='f') return c-'a'+10;
    if (c>='A' && c<='F') return c-'A'+10;
    return -1;
}
std::uint32_t decimal(const std::string& token) {
    std::uint32_t result=0;
    const auto parsed=std::from_chars(token.data(),token.data()+token.size(),result);
    require(parsed.ec==std::errc{} && parsed.ptr==token.data()+token.size(),"invalid decimal");
    return result;
}
std::uint32_t word(const std::string& token) {
    require(token.size()==10 && token[0]=='0' && token[1]=='x',"invalid word shape");
    std::uint32_t result=0;
    for (std::size_t i=2;i<10;++i) {
        const int digit=nibble(token[i]);
        require(digit>=0,"invalid word digit");
        result=(result<<4)|static_cast<std::uint32_t>(digit);
    }
    return result;
}
Bytes bytes(const std::string& token) {
    require(token.size()==40,"invalid byte field length");
    Bytes out{};
    for (std::size_t i=0;i<20;++i) {
        const int hi=nibble(token[2*i]),lo=nibble(token[2*i+1]);
        require(hi>=0 && lo>=0,"invalid byte field digit");
        out[i]=static_cast<std::uint8_t>(16*hi+lo);
    }
    return out;
}
std::string token(std::istringstream& line) {
    std::string value;
    require(static_cast<bool>(line>>value),"missing operand");
    return value;
}
std::string hexword(std::uint32_t value) {
    std::ostringstream out;
    out<<"0x"<<std::hex<<std::setw(8)<<std::setfill('0')<<value;
    return out.str();
}
std::string hexbytes(const Bytes& value) {
    constexpr char digits[]="0123456789abcdef";
    std::string out(40,'0');
    for (std::size_t i=0;i<20;++i) {
        out[2*i]=digits[value[i]>>4];
        out[2*i+1]=digits[value[i]&15];
    }
    return out;
}

// No private setters or layout access: crypt() installs all 20 bytes, and
// prefix-preserving writes move the cursor without changing those bytes.
void seed(fc::ResearchBitWriter20& writer,const Bytes& prefill,
          std::uint32_t cursor) {
    require(cursor<=160,"seed cursor outside bounded domain");
    writer.crypt(prefill);
    for (std::uint32_t pos=0;pos<cursor;) {
        const unsigned count=static_cast<unsigned>(std::min<std::uint32_t>(32,cursor-pos));
        std::uint32_t value=0;
        for (unsigned bit=0;bit<count;++bit) {
            const std::uint32_t offset=pos+bit;
            value|=std::uint32_t((prefill[offset/8]>>(offset&7))&1u)<<bit;
        }
        writer.write_bits(value,count);
        pos+=count;
    }
    const auto snapshot=writer.snapshot();
    require(snapshot.data==prefill && snapshot.bit_cursor==cursor && !snapshot.overflow,
            "public-operation seed did not preserve the requested initial state");
}

struct Case {
    char kind{};
    std::uint32_t cursor{},count{},value{};
    Bytes data{},key{};
    std::size_t line{};
};
Case parse(std::string_view text,std::size_t number) {
    std::istringstream input{std::string(text)};
    const auto command=token(input);
    Case result{};
    result.line=number;
    if (command=="B") {
        result.kind='B';
        result.cursor=decimal(token(input));
        result.count=decimal(token(input));
        result.value=word(token(input));
        result.data=bytes(token(input));
        require(result.cursor<=160 && result.count>=1 && result.count<=32 &&
                (result.count==32 || (result.value>>result.count)==0),
                "B case outside selected domain");
    } else if (command=="C") {
        result.kind='C';
        result.cursor=decimal(token(input));
        result.value=word(token(input));
        result.data=bytes(token(input));
        const float value=std::bit_cast<float>(result.value);
        require(result.cursor<=160 && std::isfinite(value) && std::fabs(value)<16385.0f,
                "C case outside selected domain");
    } else if (command=="X") {
        result.kind='X';
        result.data=bytes(token(input));
        result.key=bytes(token(input));
    } else fail("unknown action");
    std::string excess;
    require(!(input>>excess),"excess operand");
    return result;
}

std::string evaluate(const Case& c,std::size_t index) {
    fc::ResearchBitWriter20 writer;
    seed(writer,c.data,c.cursor);
    if (c.kind=='B') writer.write_bits(c.value,c.count);
    else if (c.kind=='C') writer.write_coord(std::bit_cast<float>(c.value));
    else writer.crypt(c.key); // 20-byte key repeats exactly once.
    const auto after=writer.snapshot();
    std::ostringstream out;
    out<<"{\"index\":"<<index<<",\"line\":"<<c.line
       <<",\"kind\":\""<<c.kind<<"\",\"value_bits\":\""<<hexword(c.value)
       <<"\",\"count\":"<<c.count
       <<",\"input_data\":\""<<hexbytes(c.data)
       <<"\",\"key\":\""<<hexbytes(c.key)
       <<"\",\"output_data\":\""<<hexbytes(after.data)
       <<"\",\"cursor_before\":"<<c.cursor
       <<",\"cursor_after\":"<<after.bit_cursor
       <<",\"overflow\":"<<unsigned(after.overflow)
       <<",\"evidence_class\":\"authored-owned-bit-writer\"}\n";
    return out.str();
}
std::filesystem::path research_output_path(const char* input, const char* output) {
    char* scratch_raw = nullptr;
    std::size_t scratch_length = 0;
    require(_dupenv_s(&scratch_raw, &scratch_length,
                      "FC_RESEARCH_OUTPUT_DIR") == 0,
            "cannot read FC_RESEARCH_OUTPUT_DIR");
    std::unique_ptr<char, void(*)(void*)> scratch(scratch_raw, std::free);
    require(scratch && scratch_length > 1,
            "set FC_RESEARCH_OUTPUT_DIR to external scratch");
    const std::filesystem::path requested(scratch.get());
    require(requested.is_absolute(), "scratch path must be absolute");
    const auto root = std::filesystem::weakly_canonical(requested);
    require(std::filesystem::is_directory(root), "scratch directory must exist");
    const auto target = std::filesystem::weakly_canonical(std::filesystem::path(output));
    const auto source = std::filesystem::weakly_canonical(std::filesystem::path(input));
    auto within = [](const std::filesystem::path& path,
                     const std::filesystem::path& ancestor) {
        auto a = ancestor.begin(), p = path.begin();
        for (; a != ancestor.end(); ++a, ++p) {
            if (p == path.end() || *a != *p) return false;
        }
        return true;
    };
    require(within(target, root) && target != root,
            "expectations output must be inside external scratch");
    require(target != source, "input and output paths must differ");
    const std::filesystem::path compiled_source(__FILE__);
    require(compiled_source.is_absolute(),
            "compile this probe with an absolute source path");
    auto public_tree = std::filesystem::weakly_canonical(compiled_source);
    require(std::filesystem::is_regular_file(public_tree),
            "compiled source path must still exist");
    for (int i = 0; i < 7; ++i) public_tree = public_tree.parent_path();
    require(!within(root, public_tree), "scratch cannot be inside research source tree");
    if (public_tree.filename() == "research-tools")
        require(!within(root, public_tree.parent_path()),
                "scratch cannot be inside public release tree");
    return target;
}
} // namespace

int main(int argc,char** argv) {
    try {
        require(argc==3,"usage: owned_probe actions.txt expectations.jsonl");
        std::ifstream input(argv[1],std::ios::binary);
        require(static_cast<bool>(input),"cannot open action file");
        std::ofstream output(research_output_path(argv[1],argv[2]),std::ios::binary|std::ios::trunc);
        require(static_cast<bool>(output),"cannot open expectation file");
        MxcsrMode mxcsr;
        std::string line;
        std::size_t number=0,index=0;
        while (std::getline(input,line)) {
            ++number;
            if (!line.empty() && line.back()=='\r') line.pop_back();
            if (line.empty() || line[0]=='#') continue;
            const auto c=parse(line,number);
            output<<evaluate(c,index++);
            require(index<=10000,"too many actions");
        }
        require(input.eof() && output.good() && index>0,"input/output stream failure");
        std::cout<<index<<" authored-library expectations\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr<<"owned probe failed: "<<e.what()<<'\n';
        return 1;
    }
}
