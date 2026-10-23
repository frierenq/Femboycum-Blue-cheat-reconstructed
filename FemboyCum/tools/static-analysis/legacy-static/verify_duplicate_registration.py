from legacy_env import research_root, workspace_root, required_path
from pathlib import Path
import ctypes,hashlib,json,re,struct,sys
root=workspace_root();research=research_root();out=research/'animation-layers'
ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
# Capstone is installed separately; no private dependency directory is used.
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
raw=(research/'ui-controls/nl.core.bin').read_bytes();base=0x412a0000
assert hashlib.sha256(raw).hexdigest()=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
cs=Cs(CS_ARCH_X86,CS_MODE_32);boundaries=set()
for path in out.glob('*/*.targeted.ghidra.txt'):
 boundaries.update(int(m[1],16) for m in re.finditer(r'^([0-9a-f]{8}) ',path.read_text(),re.M))
def decoded(va):return next(cs.disasm(raw[va-base:va-base+16],va))
checks={
0x4188a773:('cmp','eax, dword ptr [edx + 0xc]'),0x4188a780:('call','0x4200b31d'),0x4188a790:('je','0x4188a79b'),
0x4188a7ae:('mov','eax, dword ptr [edx + 0x18]'),0x4188a7c7:('call','dword ptr [eax]'),
0x4188a7c9:('cmp','eax, dword ptr [esi + 0x14]'),0x4188a7e0:('mov','dword ptr [esi + 0x18], eax'),
0x4188a8e2:('dec','dword ptr [ebx + 0x20]'),0x4188a8f3:('call','0x41da7be5'),
0x4188a911:('call','0x41da7b7c'),0x4188a922:('mov','dword ptr [ecx], 0x420d2508'),
0x4188a928:('mov','eax, dword ptr [eax]'),0x4188a92a:('mov','dword ptr [ecx + 4], eax'),
0x4188a93c:('mov','dword ptr [edx], eax'),0x4188a946:('call','dword ptr [eax + 4]'),
0x4188ad96:('call','0x414641c0'),0x412a6440:('lea','eax, [ecx + 4]'),0x412a6443:('ret',''),
0x414642cb:('call','0x4200b31d'),0x414642de:('je','0x41464444'),
0x4146444c:('mov','dword ptr [esi + 0x18], eax'),0x41464453:('movsd','qword ptr [esi + 0x10], xmm0'),
0x4188e1f0:('mov','ecx, edi'),0x4188e1f8:('call','0x4189cb70'),
0x4188e1fd:('mov','ecx, edi'),0x4188e205:('call','0x4189cb70'),
}
selected=[]
for va,expected in checks.items():
 i=decoded(va);assert va in boundaries and (i.mnemonic,i.op_str)==expected,(hex(va),i.mnemonic,i.op_str)
 selected.append({'va':hex(va),'core_offset':hex(va-base),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str})
assert struct.unpack_from('<II',raw,0x420d2508-base)==(0x412a6440,0x412c55d0)
rows=json.loads((out/'overlay-field-tuples.json').read_text())['rows']
duplicates=sorted((r for r in rows if r['name']=='invalidate_physics_bits'),key=lambda r:int(r['call']['va'],16))
assert [(r['call']['va'],r['member_offset']) for r in duplicates]==[('0x4188e1f8','0x34'),('0x4188e205','0x18')]
assert all(r['kind']=='int32' and r['registration_helper']=='0x4189cb70' for r in duplicates)
assert all(r['name_evidence']['text']=='invalidate_physics_bits' for r in duplicates)
sequence=next(r for r in rows if r['name']=='sequence');assert sequence['member_offset']=='0x18' and sequence['kind']=='int32'
initial=json.loads((research/'ui-controls/initial-map.json').read_text());installed=root/'outputs/FemboyLose-Build/FemboyLose-local-build/FemboyLose-local-build'
after={n:hashlib.sha256((installed/n).read_bytes()).hexdigest() for n in initial['installed_files_before']};assert after==initial['installed_files_before']
result={'date':'2026-10-18','passed':True,'scope':'Typed native property-registry duplicate replacement branch and its two layer registrations','core_sha256':initial['core_sha256'],'selected_instructions':selected,'registration_order':[{'name':r['name'],'member_offset':r['member_offset'],'call':r['call']['va']} for r in duplicates],'replacement_metadata_vtable':'0x420d2508','metadata_identity_rule':'first virtual returns descriptor address + 4','static_typed_registration_result':'later descriptor replaces earlier descriptor; final invalidate_physics_bits member offset is 0x18,matching sequence','runtime_lua_observation':'not performed','authored_runtime_tests_added':0,'installed_build_unchanged':True,'target_runtime_executed':False,'live_process_access':False,'whole_product_completion_percent':None,'limits':['Public Lua alias behavior is a static prediction from the registration path,not an in-game observation.','Reserved metamethod names and every allocation/exception branch are outside this duplicate-name contract.','Historical checkpoints preserve the earlier unresolved state; this file records the subsequent local resolution.']}
(out/'duplicate-registration-verification.json').write_text(json.dumps(result,indent=2))
print(json.dumps({'passed':True,'instruction_contracts':len(selected),'final_static_member_offset':'0x18','runtime_lua_observation':False,'installed_build_unchanged':True}))
