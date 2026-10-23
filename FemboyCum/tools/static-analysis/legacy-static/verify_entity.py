from legacy_env import research_root, workspace_root, required_path
from pathlib import Path
import ctypes,hashlib,json,re,sys
root=workspace_root();research=research_root();out=research/'entity-state'
ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
# Capstone is installed separately; no private dependency directory is used.
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
raw=(research/'ui-controls/nl.core.bin').read_bytes();base=0x412a0000
assert hashlib.sha256(raw).hexdigest()=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
cs=Cs(CS_ARCH_X86,CS_MODE_32);functions={};boundaries=set()
for path in out.glob('*/*.targeted.ghidra.txt'):
 text=path.read_text()
 for block in re.split(r'(?=^FUNCTION )',text,flags=re.M):
  if block.startswith('FUNCTION '):
   addresses=[int(m[1],16) for m in re.finditer(r'^([0-9a-f]{8}) ',block,re.M)]
   functions[int(block[9:17],16)]=addresses;boundaries.update(addresses)
def decoded(va):return next(cs.disasm(raw[va-base:va-base+16],va))
def instruction(i):return {'va':hex(i.address),'core_offset':hex(i.address-base),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str}

# Ghidra reports overlaps in the accessor. Decode these streams from actual
# branch targets, without patching or asserting recovery of invalid branches.
streams=[]
for start,end in [(0x418f46f0,0x418f471b),(0x418f4736,0x418f475c),(0x418f4770,0x418f47aa)]:
 instructions=list(cs.disasm(raw[start-base:end-base],start))
 assert instructions[-1].address+instructions[-1].size==end
 boundaries.update(i.address for i in instructions)
 streams.append({'start':hex(start),'end_exclusive':hex(end),'instructions':[instruction(i) for i in instructions]})
checks={
0x418f4719:('jne','0x418f4736'),0x418f4736:('mov','ecx, edi'),0x418f4738:('call','dword ptr [eax + 0x278]'),
0x418f4740:('je','0x418f4789'),0x418f474a:('call','dword ptr [eax + 0x28]'),0x418f474f:('jle','0x418f475c'),
0x418f4757:('cmp','eax, dword ptr [ecx + 0x18]'),0x418f475a:('jle','0x418f4770'),0x418f4770:('mov','ecx, edi'),
0x418f4772:('call','0x41b70930'),0x418f477f:('call','0x41830a40'),0x418f4789:('mov','dword ptr [esi], 0xfffffffe'),
0x418f478f:('mov','dword ptr [esi + 4], 0'),0x41b70930:('mov','eax, dword ptr [ecx + 0x9960]'),
0x4187866a:('mov','dword ptr [esi + 0x50], edx'),0x41879074:('mov','ebx, dword ptr [esi + 0x50]'),
0x41847b46:('movss','xmm0, dword ptr [edi + ebx]'),0x41847b4b:('cvtss2sd','xmm0, xmm0'),
0x41847b5b:('call','0x41db97b0'),0x418dddc6:('cvtsi2sd','xmm0, dword ptr [edi + ebx]'),
0x418dddd7:('call','0x41db97b0'),0x41850b76:('movzx','eax, byte ptr [edi + ebx]'),0x41850b7c:('call','0x41db99a0'),
0x4178e3e9:('add','ebx, edi'),0x4178e3ec:('call','0x41794870'),0x4178e3fd:('mov','dword ptr [esi], ebx'),
0x4181c310:('push','0x421798cf'),0x4181c319:('call','0x41dac0c0'),
}
selected=[]
for va,expected in checks.items():
 i=decoded(va);assert va in boundaries and (i.mnemonic,i.op_str)==expected,(hex(va),i.mnemonic,i.op_str)
 selected.append(instruction(i))
assert raw[0x421798cf-base:].split(b'\0',1)[0]==b'cannot write to a readonly variable'

# Check the common native-method and typed-property chains in the exported
# functions. Immediate stores are evidence for captured callback pointers.
contracts=[(0x418a47a0,0x41900580),(0x41900580,0x418f46f0),(0x41900580,0x418fd0c0),
(0x418289f0,0x4190a8b0),(0x41830a40,0x41882290),(0x41882290,0x4190a5e0),
(0x41858da0,0x418a2b60),(0x418974f0,0x4182c880),(0x418eb9f0,0x4186cfb0),(0x418df180,0x41824280),
(0x418a2b60,0x41874e10),(0x4182c880,0x41826ec0),(0x4186cfb0,0x4184d300),(0x41824280,0x41843050),
(0x418a2b60,0x4181c310),(0x4182c880,0x4181c310),(0x4186cfb0,0x4181c310),(0x41824280,0x4181c310),
(0x41874e10,0x41847ac0),(0x41826ec0,0x418ddd40),(0x4184d300,0x41850af0),(0x41843050,0x4178e380)]
edges=[]
for source,target in contracts:
 matches=[]
 for va in functions[source]:
  i=decoded(va)
  if (i.mnemonic in ('call','jmp') and i.op_str==hex(target)) or (i.mnemonic in ('mov','push') and i.op_str.split(', ')[-1]==hex(target)):matches.append(instruction(i))
 assert matches,(hex(source),hex(target))
 edges.append({'source':hex(source),'target':hex(target),'instructions':matches})
rows=json.loads((out/'animation-field-tuples.json').read_text())['rows']
assert len(rows)==99 and len({r['name'] for r in rows})==99
expected={'eye_yaw':('0x78','float32'),'eye_pitch':('0x7c','float32'),'abs_yaw':('0x80','float32'),
'anim_duck_amount':('0xa4','float32'),'position_current':('0xb0','vector3-reference'),'velocity':('0xc8','vector3-reference'),
'on_ground':('0x108','bool8'),'first_run_since_init':('0x4','bool8'),'last_update_frame':('0x70','int32'),'animstate_model_version':('0x344','int32')}
byname={r['name']:r for r in rows}
for name,(offset,kind) in expected.items():assert (byname[name]['member_offset'],byname[name]['kind'])==(offset,kind)
for row in rows:
 proof=[row['tuple_descriptor_pointer']['lea'],row['tuple_descriptor_pointer']['store'],row['tuple_name_pointer']['lea'],row['tuple_name_pointer']['store']]
 if row['descriptor_store']:proof.append(row['descriptor_store'])
 if 'registration_helper' in row:
  assert row['descriptor_bytes']==4 and row['member_offset'] is not None
  proof+=[row['call'],*row['argument_instructions']]
 for p in proof:
  va=int(p['va'],16);i=decoded(va);assert i.bytes.hex()==p['bytes'] and i.mnemonic+' '+i.op_str==p['instruction']
bindings=json.loads((out/'named-bindings.json').read_text())[0]['bindings']
entity=[b for b in bindings if int(b['call'],16)<0x418ab010];assert len(entity)==41
assert next(b['native_target'] for b in entity if b['name']=='get_anim_state')=='0x418a47a0'
initial=json.loads((research/'ui-controls/initial-map.json').read_text());installed=root/'outputs/FemboyLose-Build/FemboyLose-local-build/FemboyLose-local-build'
after={n:hashlib.sha256((installed/n).read_bytes()).hexdigest() for n in initial['installed_files_before']};assert after==initial['installed_files_before']
counts={kind:sum(x['kind']==kind for x in rows) for kind in sorted({x['kind'] for x in rows})}
result={'date':'2026-10-18','passed':True,'scope':'FemboyLose native entity/get_anim_state normal player path and animation-state field registration','core_sha256':initial['core_sha256'],'selected_instructions':selected,'callable_edges':edges,'accessor_branch_streams':streams,'entity_bindings':len(entity),'animation_field_tuples':len(rows),'member_registration_joins':sum('registration_helper' in x for x in rows),'field_kinds':counts,'typed_readonly_assignments':sum(x.get('readonly_setter') is not None for x in rows),'minimum_native_field_extent':'0x348','authored_runtime_tests_added':0,'installed_build_unchanged':True,'target_runtime_executed':False,'live_process_access':False,'whole_product_completion_percent':None,'limits':['Normal nonnull/player/in-range accessor path only; null and invalid-index instruction streams contain unresolved overlaps.','Binding proves the supplied core API; vendor authenticity is not cryptographically established.','Direct vector property assignment is readonly; returned nested vector userdata points to original memory,so deep immutability is not established.','Four entity-valued special properties and seven compound/array properties need further type/lifetime analysis.','No recovered animation-update or resolver algorithm is claimed.']}
(out/'verification.json').write_text(json.dumps(result,indent=2))
(out/'selected-contracts.asm.txt').write_text('\n'.join(r['va']+' '+r['bytes']+' '+r['instruction'] for r in selected)+'\n')
(out/'get-anim-state-branch-streams.asm.txt').write_text('\n\n'.join('STREAM '+s['start']+' .. '+s['end_exclusive']+'\n'+'\n'.join(r['va']+' '+r['bytes']+' '+r['instruction'] for r in s['instructions']) for s in streams)+'\n')
print(json.dumps({'passed':True,'selected_instructions':len(selected),'callable_edges':len(edges),'entity_methods':len(entity),'animation_fields':len(rows),'typed_readonly_assignments':result['typed_readonly_assignments'],'installed_build_unchanged':True}))
