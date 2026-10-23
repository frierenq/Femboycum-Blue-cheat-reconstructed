from legacy_env import research_root, workspace_root, required_path
"""Recover the binary's own method-name registry and preset callback joins."""
from pathlib import Path
import ctypes,hashlib,json,re,sys
research=research_root();root=workspace_root();out=research/'entity-state'
ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
# Capstone is installed separately; no private dependency directory is used.
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
from capstone.x86_const import X86_OP_IMM,X86_OP_MEM
raw=(research/'ui-controls/nl.core.bin').read_bytes();base=0x412a0000
assert hashlib.sha256(raw).hexdigest()=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
cs=Cs(CS_ARCH_X86,CS_MODE_32);cs.detail=True;functions={};boundaries=set()
for p in out.glob('*/*.targeted.ghidra.txt'):
    for block in re.split(r'(?=^FUNCTION )',p.read_text(),flags=re.M):
        if block.startswith('FUNCTION '):
            addresses=[int(m[1],16) for m in re.finditer(r'^([0-9a-f]{8}) ',block,re.M)]
            functions[int(block[9:17],16)]=addresses;boundaries.update(addresses)
def decoded(va):return next(cs.disasm(raw[va-base:va-base+16],va))
def record(i):return {'va':hex(i.address),'core_offset':hex(i.address-base),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str}
def text_at(va):
    assert base<=va<base+len(raw)
    value=raw[va-base:va-base+128].split(b'\0',1)[0]
    assert len(value)<128;return value.decode('ascii')
selected=[];edges=[]
def edge(source,target):
    matches=[]
    for va in functions[source]:
        i=decoded(va)
        if (i.mnemonic in ('call','jmp') and i.op_str==hex(target)) or (i.mnemonic in ('mov','push') and i.op_str.split(', ')[-1]==hex(target)):
            matches.append(record(i))
    assert matches,(hex(source),hex(target))
    edges.append({'source':hex(source),'target':hex(target),'instructions':matches})
instructions=[decoded(va) for va in functions[0x412b6250]];names=[]
for k,i in enumerate(instructions):
    if i.mnemonic!='call' or i.op_str!='0x4131bff0':continue
    dest,source=instructions[k-2:k]
    assert dest.mnemonic=='mov' and dest.op_str.startswith('ecx, 0x')
    assert source.mnemonic=='push' and source.operands[0].type==X86_OP_IMM
    object_va=dest.operands[1].imm;string_va=source.operands[0].imm
    assert object_va==0x424f470c+24*len(names)
    proof=[record(x) for x in [dest,source,i]];selected.extend(proof)
    names.append({'index':len(names),'registry_offset':hex(object_va-0x424f470c),
        'string_object_va':hex(object_va),'text_va':hex(string_va),'text':text_at(string_va),'initializer':proof})
assert len(names)==37
by_offset={int(n['registry_offset'],16):n for n in names}
edge(0x4131bff0,0x42033bb0);edge(0x4131bff0,0x4200c9a0)
setup=[decoded(va) for va in functions[0x418a3ec0] if 0x418a3f37<=va<0x418a400b]
starts=[k for k,i in enumerate(setup) if i.mnemonic=='call' and i.op_str=='0x412b6250']
assert len(starts)==5
expected=[('__lt',0x418dc920,0x198),('__le',0x41863000,0x1b0),('__eq',0x41855090,0x180),
          ('__pairs',0x41910a40,0x288),('__tostring',0x41893e80,0x90)]
bindings=[]
for n,(name,callback,offset) in enumerate(expected):
    window=setup[starts[n]:starts[n+1] if n+1<len(starts) else len(setup)]
    caps=[i for i in window if i.mnemonic=='cmp' and i.operands[0].type==X86_OP_MEM and i.op_str.endswith(', 0x10')]
    captures=[i for i in window if i.mnemonic=='mov' and i.op_str.endswith(', '+hex(callback))]
    assert len(caps)==len(captures)==1 and caps[0].operands[0].mem.disp-0x14==offset
    assert by_offset[offset]['text']==name
    proof=[record(window[0]),record(caps[0]),record(captures[0])];selected.extend(proof)
    bindings.append({'method_name':name,'registry_offset':hex(offset),'callback':hex(callback),'setup_instructions':proof})
for source,target in [(0x41910a40,0x41870f30),(0x41870f30,0x41833f70),
                      (0x41833f70,0x421783ab),(0x41833f70,0x41dac0c0),
                      (0x41893e80,0x41889eb0)]:edge(source,target)
assert text_at(0x421783ab)=="sol: cannot call '__pairs/pairs' on type '%s': it is not recognized as a container"
comparisons=[]
for entry,wanted in [(0x418dc920,'setl'),(0x41863000,'setle'),(0x41855090,'sete')]:
    ins=[decoded(va) for va in functions[entry]]
    match=[i for i in ins if i.mnemonic==wanted];assert len(match)==1
    conversions=[i for i in ins if i.mnemonic=='cvttsd2si'];assert len(conversions)==2
    proof=[record(i) for i in conversions+match];selected.extend(proof)
    comparisons.append({'callback':hex(entry),'integer_comparison':wanted,'conversion_instructions':proof,
        'complete_lua_argument_conversion_recovered':False})
initial=json.loads((research/'ui-controls/initial-map.json').read_text())
installed=root/'outputs/FemboyLose-Build/FemboyLose-local-build/FemboyLose-local-build'
after={n:hashlib.sha256((installed/n).read_bytes()).hexdigest() for n in initial['installed_files_before']}
assert after==initial['installed_files_before']
unique={i['va']:i for i in selected}
result={'date':'2026-10-18','passed':True,'core_sha256':initial['core_sha256'],
    'scope':'Native 37-string metamethod registry, five explicit preset method entries and pairs-error path',
    'metamethod_names':names,'preset_explicit_entries':bindings,'comparison_slices':comparisons,
    'selected_original_instructions':list(unique.values()),'captured_pointer_and_call_edges':edges,
    'pairs_error_literal':text_at(0x421783ab),'authored_runtime_tests_added':0,
    'target_runtime_executed':False,'live_process_access':False,'installed_build_unchanged':True,'whole_product_completion_percent':None,
    'limits':['This establishes the explicit bootstrap entries, not the full class registry, public argument ABI or every later metatable mutation.',
              'No indexed-array extent or container behavior is inferred from the stored int pointer; the observed pairs callback raises an error.',
              'Comparisons use native truncating numeric conversions; invalid/out-of-range numbers, userdata coercion and error paths are not reconstructed in a C++ model.',
              'The typed pointer/getter projection does not establish animation algorithms or deep mutability.']}
(out/'metamethod-names.json').write_text(json.dumps(names,indent=2))
(out/'preset-metamethods-verification.json').write_text(json.dumps(result,indent=2))
print(json.dumps({'passed':True,'registry_names':len(names),'preset_explicit_entries':len(bindings),'original_instruction_contracts':len(unique),'callable_edges':len(edges),'installed_build_unchanged':True}))
