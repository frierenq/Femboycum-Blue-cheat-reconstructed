from legacy_env import research_root, workspace_root, required_path
"""Check two-pass rotation transformation and original finite fmod path."""
from pathlib import Path
import ctypes,hashlib,json,re,struct,sys
research=research_root();root=workspace_root();out=research/'antiaim-accessors'
ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
# Capstone is installed separately; no private dependency directory is used.
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
raw=(research/'ui-controls/nl.core.bin').read_bytes();base=0x412a0000
assert hashlib.sha256(raw).hexdigest()=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
cs=Cs(CS_ARCH_X86,CS_MODE_32);functions={};boundaries=set()
for p in out.glob('*/*.targeted.ghidra.txt'):
    for block in re.split(r'(?=^FUNCTION )',p.read_text(),flags=re.M):
        if block.startswith('FUNCTION '):
            addresses=[int(m[1],16) for m in re.finditer(r'^([0-9a-f]{8}) ',block,re.M)]
            functions[int(block[9:17],16)]=addresses;boundaries.update(addresses)
def decoded(va):return next(cs.disasm(raw[va-base:va-base+16],va))
def record(i):return {'va':hex(i.address),'core_offset':hex(i.address-base),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str}
selected=[];edges=[];streams=[]
def check(va,mnemonic,operands):
    i=decoded(va);assert va in boundaries and (i.mnemonic,i.op_str)==(mnemonic,operands),(hex(va),i.mnemonic,i.op_str)
    selected.append(record(i))
def edge(source,target,wanted=None):
    matches=[record(decoded(va)) for va in functions[source] if decoded(va).mnemonic in ('call','jmp') and decoded(va).op_str==hex(target)]
    assert matches and (wanted is None or len(matches)==wanted),(hex(source),hex(target),len(matches))
    edges.append({'source':hex(source),'target':hex(target),'instructions':matches})
for start,end in [(0x41958980,0x41958b0c),(0x42026d1b,0x42026d69),
                  (0x420498d0,0x420498de),(0x420507f0,0x420507fd)]:
    ins=list(cs.disasm(raw[start-base:end-base],start));assert ins[-1].address+ins[-1].size==end
    # Ghidra groups WAIT+FNSTSW as FSTSW at 0x420498d4. Capstone splits
    # the same original 9b df e0 bytes into WAIT at d4 and FNSTSW at d5.
    assert raw[0x420498d4-base:0x420498d7-base]==bytes.fromhex('9bdfe0')
    assert all(i.address in boundaries or (i.address==0x420498d5 and i.mnemonic=='fnstsw' and i.op_str=='ax') for i in ins)
    streams.append({'start':hex(start),'end_exclusive':hex(end),
        'decoder_grouping_note':'WAIT/FNSTSW split at 0x420498d4/d5 is Ghidra FSTSW over the same bytes' if start==0x420498d0 else None,
        'instructions':[record(i) for i in ins]})
checks={
    0x4195898f:('movss','xmm0, dword ptr [0x424f46b8]'),
    0x419589b5:('cmp','ax, 2'),0x419589b9:('je','0x419589d5'),
    0x419589cf:('cmp','ax, 1'),0x419589d3:('jne','0x419589d8'),0x419589d5:('xorps','xmm1, xmm1'),
    0x419589d8:('movsd','xmm0, qword ptr [0x4206cdc8]'),0x419589e9:('cvtss2sd','xmm0, xmm1'),
    0x419589f7:('fstp','dword ptr [esp + 0x28]'),0x41958a09:('addss','xmm2, xmm1'),
    0x41958a0d:('movss','xmm0, dword ptr [0x4206cdd4]'),0x41958a15:('cmpltss','xmm0, xmm1'),
    0x41958a32:('cmpltss','xmm2, dword ptr [0x4206cddc]'),
    0x41958a5c:('cmp','ax, 2'),0x41958a60:('je','0x41958a7b'),
    0x41958a75:('cmp','ax, 1'),0x41958a79:('jne','0x41958a7e'),0x41958a7b:('xorps','xmm1, xmm1'),
    0x41958a7e:('movsd','xmm0, qword ptr [0x4206cdc8]'),0x41958a8f:('cvtss2sd','xmm0, xmm1'),
    0x41958a9d:('fstp','dword ptr [esp + 0x20]'),0x41958abb:('cmpltss','xmm2, xmm0'),
    0x41958ad4:('cmpltss','xmm1, dword ptr [0x4206cddc]'),0x41958aea:('movss','dword ptr [esp + 0x24], xmm1'),
    0x41958af0:('fld','dword ptr [esp + 0x24]'),
    0x42026d24:('mov','esi, 0x7f80'),0x42026d29:('movzx','eax, word ptr [ecx + 2]'),
    0x42026d37:('test','al, 0x7f'),0x42026d46:('push','2'),
    0x42026d4b:('test','eax, 0xffff7fff'),0x42026d5e:('test','dx, dx'),
    0x42026d61:('setne','al'),0x42026d64:('sub','eax, 2'),
    0x42031040:('mov','edx, 0x4216a840'),0x42031045:('jmp','0x42048809'),
    0x420498d0:('fxch','st(1)'),0x420498d2:('fprem',''),0x420498d9:('jp','0x420498d2'),
    0x420507f0:('fstp','st(0)'),0x420507f2:('fstp','st(0)'),0x420507f4:('fldz',''),
    0x420507f6:('test','ch, ch'),0x420507f8:('je','0x420507fc'),0x420507fa:('fchs',''),
    # Checked references only; complete writer/consumer paths remain partial.
    0x413321a4:('movss','dword ptr [0x424f46b8], xmm0'),
    0x41345906:('movss','xmm0, dword ptr [eax + 0x80]'),
    0x41345918:('movss','dword ptr [0x424f46b8], xmm0'),
    0x4199b5b3:('movss','xmm0, dword ptr [0x424f46b8]'),
}
for va,pair in checks.items():check(va,*pair)
edge(0x41958980,0x42026d1b,4);edge(0x41958980,0x42031040,2)
edge(0x42031040,0x420489cb,2);edge(0x42031040,0x42050725,1);edge(0x42031040,0x4204884a,1)
assert raw[0x4216a840-base:0x4216a846-base]==b'\x04fmod\0'
constants={0x4206cdd0:0xc3b40000,0x4206cdd4:0x43340000,0x4206cdd8:0x43b40000,0x4206cddc:0xc3340000}
for va,bits in constants.items():assert struct.unpack_from('<I',raw,va-base)[0]==bits
assert struct.unpack_from('<d',raw,0x4206cdc8-base)[0]==360.0
selector=raw[0x4216bfae-base:0x4216bfae-base+16]
assert selector.hex()=='080408080804080800040c0800040c08'
def class_key(status_high):
    # Exact SHL/SAR/ROL byte expressions in the original FXAM dispatcher.
    shifted=(status_high<<1)&255
    signed=shifted if shifted<128 else shifted-256
    shifted=(signed>>1)&255
    return ((shifted<<1)|(shifted>>7))&15
cases=[]
for kind,status in [('normal+',4),('normal-',6),('zero+',0x40),('zero-',0x42)]:
    index=selector[class_key(status)]<<2 # denominator 360 has selector 0.
    target=struct.unpack_from('<I',raw,0x4216a840+0x10+index-base)[0]
    assert target==(0x420498d0 if kind.startswith('normal') else 0x420507f0)
    cases.append({'input_class':kind,'selector_offset':hex(index),'handler':hex(target)})
binding=next(b for b in json.loads((out/'named-bindings.json').read_text())[0]['bindings'] if b['name']=='get_rotation')
assert binding['native_target']=='0x41958980'
tests=json.loads((out/'rotation-semantic-tests.json').read_text());assert tests['passed'] and tests['semantic_checks']==36
initial=json.loads((research/'ui-controls/initial-map.json').read_text())
installed=root/'outputs/FemboyLose-Build/FemboyLose-local-build/FemboyLose-local-build'
after={n:hashlib.sha256((installed/n).read_bytes()).hexdigest() for n in initial['installed_files_before']}
assert after==initial['installed_files_before']
result={'date':'2026-10-18','passed':True,'core_sha256':initial['core_sha256'],
    'scope':'get_rotation numeric transformation, binary32 classification and finite/zero original fmod handlers; complete feature writers/ABI excluded',
    'binding':binding,'selected_original_instructions':selected,'complete_local_streams':streams,
    'call_edges':edges,'finite_zero_remainder_dispatch':cases,'tests':tests,
    'source_global':'0x424f46b8','numeric_passes':2,'native_remainder_descriptor':'0x4216a840',
    'preserves_both_180_endpoints':True,'preserves_signed_zero':True,
    'whole_numeric_transformation_recovered':True,'whole_rotation_feature_recovered':False,
    'original_crt_fpu_environment_reimplemented':False,'target_runtime_executed':False,'live_process_access':False,
    'installed_build_unchanged':True,'whole_product_completion_percent':None,
    'limits':['The model takes an authored input value and uses the host standard fmod for ordinary finite/zero operands.',
              'Original CRT error reporting/control-word/exception behavior and public Lua ABI are not reimplemented.',
              'References in 0x4132eab0/0x41344740/0x4199b590 are verified local reads/writes, not complete writer/consumer algorithms.',
              'No anti-aim/resolver or target-selection completion is claimed.']}
(out/'rotation-verification.json').write_text(json.dumps(result,indent=2))
print(json.dumps({'passed':True,'original_instruction_contracts':len(selected),'complete_local_streams':len(streams),'authored_semantic_checks':36,'numeric_transformation_recovered':True,'whole_rotation_feature_recovered':False,'installed_build_unchanged':True}))
