from legacy_env import research_root, workspace_root, required_path
from pathlib import Path
import ctypes,hashlib,json,re,sys
root=workspace_root();research=research_root();out=research/'animation-layers'
ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
# Capstone is installed separately; no private dependency directory is used.
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
raw=(research/'ui-controls/nl.core.bin').read_bytes();base=0x412a0000
assert hashlib.sha256(raw).hexdigest()=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
cs=Cs(CS_ARCH_X86,CS_MODE_32);functions={};boundaries=set()
for path in out.glob('*/*.targeted.ghidra.txt'):
 for block in re.split(r'(?=^FUNCTION )',path.read_text(),flags=re.M):
  if block.startswith('FUNCTION '):
   addresses=[int(m[1],16) for m in re.finditer(r'^([0-9a-f]{8}) ',block,re.M)]
   functions[int(block[9:17],16)]=addresses;boundaries.update(addresses)
def decoded(va):return next(cs.disasm(raw[va-base:va-base+16],va))
def record(i):return {'va':hex(i.address),'core_offset':hex(i.address-base),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str}
checks={
0x4186b5c4:('jmp','0x41836740'),0x41897064:('jmp','0x418a15d0'),
0x4183678f:('mov','ecx, esp'),0x41836791:('push','dword ptr [eax + 0x30]'),0x41836794:('call','0x41b45ed0'),
0x41b45ed7:('test','ecx, ecx'),0x41b45ed9:('je','0x41b45ee6'),0x41b45ee1:('call','dword ptr [eax + 0x28]'),
0x41b45ee6:('mov','eax, 0xffffffff'),0x41b45eeb:('mov','dword ptr [esi], eax'),
0x418367e4:('call','0x413919a0'),0x418367f7:('mov','eax, dword ptr [esp]'),0x418367fa:('mov','dword ptr [esi], eax'),
0x4190f5fa:('mov','ebx, dword ptr [ecx + 0x18]'),0x4190f5fd:('mov','edi, dword ptr [ecx + 0x30]'),
0x4190f949:('mov','eax, dword ptr [0x424f4ae8]'),0x4190f94e:('mov','ecx, dword ptr [eax + edi]'),
0x4190f951:('mov','eax, 0xffffffff'),0x4190f956:('test','ecx, ecx'),0x4190f958:('je','0x4190f996'),
0x4190f95a:('mov','edx, dword ptr [ecx]'),0x4190f95c:('test','edx, edx'),0x4190f95e:('je','0x4190f996'),
0x4190f991:('mov','ecx, edi'),0x4190f993:('push','ebx'),0x4190f994:('call','eax'),
0x418a1654:('cvtsi2sd','xmm0, edi'),0x418a1664:('call','0x41db97b0'),
}
selected=[]
for va,expected in checks.items():
 i=decoded(va);assert va in boundaries and (i.mnemonic,i.op_str)==expected,(hex(va),i.mnemonic,i.op_str)
 selected.append(record(i))
contracts=[(0x4188ccd0,0x4186b5c0),(0x4188ccd0,0x41897060),(0x4188ccd0,0x4177df00),
(0x41836740,0x41b45ed0),(0x41836740,0x413919a0),(0x418a15d0,0x4190f5b0),(0x4177df00,0x421770a1)]
edges=[]
for source,target in contracts:
 matches=[]
 for va in functions[source]:
  i=decoded(va)
  if (i.mnemonic in ('call','jmp') and i.op_str==hex(target)) or (i.mnemonic in ('mov','push') and i.op_str.split(', ')[-1]==hex(target)):matches.append(record(i))
 assert matches,(hex(source),hex(target));edges.append({'source':hex(source),'target':hex(target),'instructions':matches})
assert raw[0x421770a1-base:].split(b'\0',1)[0]==b'cannot write to a readonly property'
target=(0xad235fd0^0x6bfb3897)-0x6d88215a+0x10df817d;target&=0xffffffff
target^=0x1ad82964;target=(target-0x48c7596e)&0xffffffff
assert target==0x283094a0 and not base<=target<base+len(raw)
offset_body=[record(i) for i in cs.disasm(raw[0x4190f960-base:0x4190f983-base],0x4190f960)]
initial=json.loads((research/'ui-controls/initial-map.json').read_text());installed=root/'outputs/FemboyLose-Build/FemboyLose-local-build/FemboyLose-local-build'
after={n:hashlib.sha256((installed/n).read_bytes()).hexdigest() for n in initial['installed_files_before']};assert after==initial['installed_files_before']
result={'date':'2026-10-18','passed':True,'scope':'Native animation-layer owner conversion and activity lookup boundary','core_sha256':initial['core_sha256'],'selected_instructions':selected,'captured_pointer_and_call_edges':edges,'external_activity_target_in_stored_image':hex(target),'external_target_constant_instructions':offset_body,'external_target_present_in_core':False,'owner_pointer_member':'0x30','sequence_member':'0x18','owner_null_conversion':-1,'activity_missing_header_result':-1,'native_header_offset_cache':'0x424f4ae8','authored_runtime_tests_added':0,'installed_build_unchanged':True,'target_runtime_executed':False,'live_process_access':False,'whole_product_completion_percent':None,'limits':['Activity header-offset lookup/cache initialization contains overlapping invalid paths and is only partially recovered.','Stored external target address is not a verified address in the running game.','No external target code was read or executed; its implementation is absent from this core.','Owner entity userdata lifetime and invalid entity handling remain incomplete.','Duplicate-property registration semantics are still open.']}
(out/'special-properties-verification.json').write_text(json.dumps(result,indent=2))
print(json.dumps({'passed':True,'instruction_contracts':len(selected),'callable_edges':len(edges),'external_dependency_absent_from_core':True,'installed_build_unchanged':True}))
