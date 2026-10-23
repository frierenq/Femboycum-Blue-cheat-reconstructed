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
0x41b73985:('cmp','edx, 0xe'),0x41b73988:('jg','0x41b739b9'),0x41b739b3:('imul','esi, edx, 0x38'),
0x41b739b6:('add','esi, dword ptr [eax + ecx]'),0x41b6d138:('mov','esi, dword ptr [eax + ecx]'),
0x41876d79:('mov','dword ptr [esp + 0xc], 0x41844c40'),0x41876dba:('call','0x4190c760'),
0x418929e6:('movss','xmm0, dword ptr [edi + ebx]'),0x418929eb:('cvtss2sd','xmm0, xmm0'),
0x418929fb:('call','0x41db97b0'),0x41892ed6:('cvtsi2sd','xmm0, dword ptr [edi + ebx]'),
0x41892ee7:('call','0x41db97b0'),0x41836894:('mov','edi, dword ptr [edi + ebx]'),0x418368bb:('call','0x41db99d0'),
0x41884fed:('cmp','eax, 1'),0x41884ff2:('cmp','eax, 2'),0x41885060:('cmp','eax, 3'),
0x41885065:('push','0x41876d70'),0x418850b5:('push','0x41842ee0'),
0x418552d5:('xor','eax, eax'),0x418552e9:('mov','dword ptr [ebp - 0x20], eax'),
0x418552ed:('call','0x41b73970'),0x418552fe:('mov','dword ptr [ebp - 0x38], eax'),
0x41855309:('call','0x4186c000'),0x41855311:('inc','eax'),0x41855318:('jne','0x418552e0'),
}
selected=[]
for va,expected in checks.items():
 i=decoded(va);assert va in boundaries and (i.mnemonic,i.op_str)==expected,(hex(va),i.mnemonic,i.op_str)
 selected.append(record(i))
contracts=[(0x418f7050,0x41884fd0),(0x41884fd0,0x41842ee0),(0x41884fd0,0x41876d70),
(0x41842ee0,0x41855200),(0x41855200,0x41b6d100),(0x41855200,0x41b73970),(0x41855200,0x4186c000),
(0x41876d70,0x4190c760),(0x41876d70,0x41844c40),(0x41844c40,0x41b73970),(0x41844c40,0x4189a020),
(0x4189a020,0x418dd500),(0x4189a020,0x418fbfb0),(0x4186c000,0x418fbfb0),(0x418dd500,0x419032a0),(0x419032a0,0x41821a50),
(0x41841bd0,0x418412b0),(0x4189cb70,0x4188a590),(0x418e4310,0x418431f0),
(0x418412b0,0x4183e0d0),(0x4188a590,0x4184f900),(0x418431f0,0x4188b340),
(0x418412b0,0x4181c310),(0x4188a590,0x4181c310),(0x418431f0,0x4181c310),
(0x4183e0d0,0x41892960),(0x4184f900,0x41892e50),(0x4188b340,0x41836830)]
edges=[]
for source,target in contracts:
 matches=[]
 for va in functions[source]:
  i=decoded(va)
  if (i.mnemonic in ('call','jmp') and i.op_str==hex(target)) or (i.mnemonic in ('mov','push') and i.op_str.split(', ')[-1]==hex(target)):matches.append(record(i))
 assert matches,(hex(source),hex(target))
 edges.append({'source':hex(source),'target':hex(target),'instructions':matches})
mask=0xffffffff
def rol(v,n):n&=31;return ((v<<n)|(v>>(32-n)))&mask if n else v
def ror(v,n):return rol(v,32-(n&31))
# Constant-only folding of the native offset expressions. No code emulation.
layer=0x976109d3^0x533657c5;layer=(layer-0x28a75f79)&mask;layer^=0x02affe9f
layer=ror(rol(ror(layer,4),30),14);assert layer==0x2990
count=(0x7a7903b0-0x1076b34a)&mask;count^=0x235716dd;count=rol(ror(count,28),30)
count=(count-0x62846eff+0x3d2f7dae)&mask;assert count==0x299c
fold_proofs=[]
for a,z in [(0x41b7398a,0x41b739ad),(0x41b6d10f,0x41b6d132)]:
 fold_proofs.extend(record(i) for i in cs.disasm(raw[a-base:z-base],a))
obj=json.loads((out/'overlay-field-tuples.json').read_text());rows=obj['rows'];assert len(rows)==19
members=[r for r in rows if 'registration_helper' in r];assert len(members)==14
assert sum(r['name'] is not None for r in rows)==16
assert obj['duplicate_names']==['invalidate_physics_bits']
for row in rows:
 proof=[row['tuple_descriptor_pointer']['lea'],row['tuple_descriptor_pointer']['store'],row['tuple_name_pointer']['lea'],row['tuple_name_pointer']['store']]
 if row['descriptor_store']:proof.append(row['descriptor_store'])
 if 'registration_helper' in row:proof+=[row['call'],*row['argument_instructions']]
 for p in proof:
  i=decoded(int(p['va'],16));assert i.bytes.hex()==p['bytes'] and i.mnemonic+' '+i.op_str==p['instruction']
expected={'playback_rate':('0x28','float32'),'weight_delta_rate':('0x24','float32'),'weight':('0x20','float32'),
'cycle':('0x2c','float32'),'prev_cycle':('0x1c','float32'),'sequence':('0x18','int32'),'order':('0x14','int32')}
for name,contract in expected.items():
 row=next(r for r in rows if r['name']==name);assert (row['member_offset'],row['kind'])==contract
types=json.loads((research/'entity-state/native-types.json').read_text())
assert {x['native_type'] for x in types['rows']}=={'lua::C_GameRulesSafe','lua::PlayerResource','CCSGOPlayerAnimState','CCSGOPlayerAnimState *','C_AnimationLayer','C_AnimationLayer *'}
for row in types['rows']:
 for p in row['selected_instructions']:
  i=decoded(int(p['va'],16));assert i.bytes.hex()==p['bytes'] and i.mnemonic+' '+i.op_str==p['instruction']
initial=json.loads((research/'ui-controls/initial-map.json').read_text());installed=root/'outputs/FemboyLose-Build/FemboyLose-local-build/FemboyLose-local-build'
after={n:hashlib.sha256((installed/n).read_bytes()).hexdigest() for n in initial['installed_files_before']};assert after==initial['installed_files_before']
result={'date':'2026-10-18','passed':True,'scope':'FemboyLose native animation-overlay access,selected layer fields and type literals','core_sha256':initial['core_sha256'],'selected_instructions':selected,'callable_edges':edges,'offset_expression_instructions':fold_proofs,'layer_pointer_field':hex(layer),'layer_count_field':hex(count),'layer_stride':'0x38','indexed_leaf_guard':'signed index <= 14; lower-bound and current-count checks absent in this leaf','field_tuple_rows':len(rows),'named_tuples':16,'typed_member_joins':14,'duplicate_names_unresolved':obj['duplicate_names'],'decoded_type_literals':6,'authored_runtime_tests_added':0,'installed_build_unchanged':True,'target_runtime_executed':False,'live_process_access':False,'whole_product_completion_percent':None,'limits':['Normal entity paths are partial because invalid-path instruction streams overlap.','Duplicate property replacement semantics,activity and owner callbacks remain unresolved.','Integer conversion and complete Lua overload error behavior need further validation.','Native type literals identify this supplied core; they do not prove vendor authenticity.','Animation update,resolver and playback modification algorithms are not recovered here.']}
(out/'verification.json').write_text(json.dumps(result,indent=2))
(out/'selected-contracts.asm.txt').write_text('\n'.join(r['va']+' '+r['bytes']+' '+r['instruction'] for r in selected)+'\n')
print(json.dumps({'passed':True,'instruction_contracts':len(selected),'callable_edges':len(edges),'typed_layer_member_joins':14,'decoded_type_literals':6,'installed_build_unchanged':True}))
