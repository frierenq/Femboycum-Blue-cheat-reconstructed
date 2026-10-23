from legacy_env import research_root, workspace_root, required_path
"""Original-byte verification for six API joins and the complete math leaf."""
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
selected=[];edges=[]
def check(va,mnemonic,operands):
    i=decoded(va);assert va in boundaries and (i.mnemonic,i.op_str)==(mnemonic,operands),(hex(va),i.mnemonic,i.op_str)
    selected.append(record(i))
def edge(source,target):
    matches=[]
    for va in functions[source]:
        i=decoded(va)
        if (i.mnemonic in ('call','jmp') and i.op_str==hex(target)) or (i.mnemonic in ('mov','push') and i.op_str.split(', ')[-1]==hex(target)):
            matches.append(record(i))
    assert matches,(hex(source),hex(target));edges.append({'source':hex(source),'target':hex(target),'instructions':matches})
bindings=json.loads((out/'named-bindings.json').read_text())[0]['bindings']
expected={'inverter':'0x41a2d810','override_hidden_yaw_offset':'0x419de250',
          'override_hidden_pitch':'0x419453b0','get_max_desync':'0x419c6620',
          'get_rotation':'0x41958980','get_target':'0x419c8400'}
assert {b['name']:b['native_target'] for b in bindings}==expected
for b in bindings:
    r=b['slot_store'];i=decoded(int(r['va'],16));assert i.bytes.hex()==r['bytes'] and i.mnemonic+' '+i.op_str==r['instruction'];selected.append(record(i))
    for va,mnemonic,operands in b['registration_instructions']:check(int(va,16),mnemonic,operands)
    # These five helpers consume length/capacity name strings and use the name
    # in their Lua field-set path; they are not enum metamethod helpers.
    helper=int(b['helper'],16);edge(helper,0x41db9e10)
body=list(cs.disasm(raw[0x41b707e0-base:0x41b70863-base],0x41b707e0))
assert body[-1].mnemonic=='ret' and body[-1].address+body[-1].size==0x41b70863
assert all(i.address in boundaries for i in body)
checks={
    0x41b707e0:('movss','xmm2, dword ptr [ecx + 0x11c]'),0x41b707e8:('mulss','xmm2, dword ptr [0x4206da3c]'),
    0x41b707f0:('movss','xmm1, dword ptr [ecx + 0xa4]'),0x41b707f8:('xorps','xmm3, xmm3'),
    0x41b707fb:('movss','xmm4, dword ptr [ecx + 0xf8]'),0x41b70803:('maxss','xmm4, xmm3'),
    0x41b70807:('movss','xmm0, dword ptr [0x4205a554]'),0x41b7080f:('minss','xmm4, xmm0'),
    0x41b70813:('addss','xmm2, dword ptr [0x4206da40]'),0x41b7081b:('mulss','xmm2, xmm4'),
    0x41b7081f:('addss','xmm0, xmm2'),0x41b70823:('ucomiss','xmm3, xmm1'),
    0x41b70826:('jae','0x41b70850'),0x41b70828:('maxss','xmm3, dword ptr [ecx + 0xfc]'),
    0x41b70830:('minss','xmm3, dword ptr [0x4205a554]'),0x41b70838:('movss','xmm4, dword ptr [0x4205a530]'),
    0x41b70840:('subss','xmm4, xmm2'),0x41b70844:('mulss','xmm1, xmm3'),
    0x41b70848:('mulss','xmm1, xmm4'),0x41b7084c:('addss','xmm0, xmm1'),
    0x41b70850:('push','eax'),0x41b70851:('mulss','xmm0, dword ptr [ecx + 0x338]'),
    0x41b70859:('movss','dword ptr [esp], xmm0'),0x41b7085e:('fld','dword ptr [esp]'),
    0x41b70861:('pop','eax'),0x41b70862:('ret',''),
    0x419c6655:('test','ecx, ecx'),0x419c6657:('je','0x419c66c5'),
    0x419c667e:('call','0x41b6ff10'),0x419c6685:('je','0x419c66c5'),
    0x419c66b5:('call','0x41b70930'),0x419c66ba:('test','eax, eax'),
    0x419c66bc:('je','0x419c66c5'),0x419c66be:('mov','ecx, eax'),
    0x419c66c0:('jmp','0x41b707e0'),0x419c66c5:('fld','dword ptr [0x4209bb94]'),
    0x41a2d810:('mov','eax, dword ptr [0x42500648]'),0x41a2d815:('movzx','eax, byte ptr [eax + 0x2b5]'),
    0x419de250:('movss','xmm0, dword ptr [esp + 4]'),0x419de25b:('movss','dword ptr [eax + 0x80], xmm0'),
    0x419de263:('mov','byte ptr [eax + 0x84], 1'),
    0x419453b0:('movss','xmm0, dword ptr [esp + 4]'),0x419453bb:('movss','dword ptr [eax + 0x88], xmm0'),
    0x419453c3:('mov','byte ptr [eax + 0x8c], 1'),
}
for va,pair in checks.items():check(va,*pair)
constants={0x4206da3c:0xbe99999a,0x4206da40:0xbe4ccccc,0x4205a530:0xbf000000,0x4205a554:0x3f800000,0x4209bb94:0x42680000}
for va,bits in constants.items():assert struct.unpack_from('<I',raw,va-base)[0]==bits
field_names={'0x11c':'walk_run_transition','0xf8':'speed_as_portion_of_walk_top_speed',
             '0xfc':'speed_as_portion_of_crouch_top_speed','0xa4':'anim_duck_amount','0x338':'aim_yaw_max'}
fields=json.loads((research/'entity-state/animation-field-tuples.json').read_text())['rows']
for offset,name in field_names.items():assert next(r for r in fields if r['name']==name)['member_offset']==offset
tests=json.loads((out/'semantic-tests.json').read_text());assert tests['passed'] and tests['semantic_checks']==29
initial=json.loads((research/'ui-controls/initial-map.json').read_text())
installed=root/'outputs/FemboyLose-Build/FemboyLose-local-build/FemboyLose-local-build'
after={n:hashlib.sha256((installed/n).read_bytes()).hexdigest() for n in initial['installed_files_before']}
assert after==initial['installed_files_before']
unique={i['va']:i for i in selected}
result={'date':'2026-10-18','passed':True,'core_sha256':initial['core_sha256'],
    'scope':'Six API name/function joins; complete 0x41b707e0 math leaf, inverter read and two hidden-angle write leaves; public API/engine integration partial',
    'bindings':bindings,'selected_original_instructions':list(unique.values()),'complete_math_leaf':[record(i) for i in body],
    'name_helper_edges':edges,'input_fields':field_names,'constants':[{'va':hex(va),'bits':hex(bits),'float':struct.unpack('<f',struct.pack('<I',bits))[0]} for va,bits in constants.items()],
    'tests':tests,'observed_wrapper_fallback_float':58.0,'whole_math_leaf_recovered':True,'whole_public_get_max_desync_recovered':False,
    'whole_rotation_or_target_selection_recovered':False,'target_runtime_executed':False,'live_process_access':False,
    'installed_build_unchanged':True,'whole_product_completion_percent':None,
    'limits':['Public API guards/argument marshaling, profile/context lifetime, reset/consumption and callers remain incomplete.',
              'The scalar model uses explicit SSE ordering and authored fixtures under ordinary masked floating-point exceptions; signaling-NaN/exception flags are not reproduced.',
              'The two angle setters store payload/activation flags but their consuming/resetting algorithms remain open.',
              'The recovered maximum-yaw calculation is not a complete resolver, animation system or anti-aim implementation.']}
(out/'verification.json').write_text(json.dumps(result,indent=2))
(out/'selected-contracts.asm.txt').write_text('\n'.join(i['va']+' '+i['bytes']+' '+i['instruction'] for i in unique.values())+'\n')
print(json.dumps({'passed':True,'api_bindings':6,'original_instruction_contracts':len(unique),'authored_semantic_checks':29,'whole_math_leaf_recovered':True,'full_public_api_recovered':False,'installed_build_unchanged':True}))
