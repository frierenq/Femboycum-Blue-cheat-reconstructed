from legacy_env import research_root, workspace_root, required_path
from pathlib import Path
import ctypes,hashlib,json,re,sys
root=workspace_root();research=research_root();out=research/'animation-layers'
ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
# Capstone is installed separately; no private dependency directory is used.
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
from capstone.x86_const import X86_OP_IMM,X86_OP_MEM,X86_OP_REG
raw=(research/'ui-controls/nl.core.bin').read_bytes();base=0x412a0000
assert hashlib.sha256(raw).hexdigest()=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
cs=Cs(CS_ARCH_X86,CS_MODE_32);cs.detail=True
def record(i):return {'va':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str}
objects=json.loads((research/'entity-state/named-bindings.json').read_text())[0]['name_objects']
names={int(x['frame_offset'],16):x for x in objects if 0x418bf400<int(x['at'],16)<0x418c1eeb}
mem={};stores={};regs={};ptrs={}
for i in cs.disasm(raw[0x418a5770-base:0x418c1f1b-base],0x418a5770):
 a=i.operands
 if i.mnemonic=='mov' and len(a)==2 and a[0].type==X86_OP_MEM and cs.reg_name(a[0].mem.base)=='esi' and a[1].type==X86_OP_IMM:
  size=a[0].size;offset=a[0].mem.disp;v=a[1].imm&((1<<(size*8))-1)
  for k,c in enumerate(v.to_bytes(size,'little')):mem[offset+k]=c;stores[offset+k]=record(i)
for i in cs.disasm(raw[0x418c1f1b-base:0x418c20ef-base],0x418c1f1b):
 a=i.operands
 if i.mnemonic=='lea' and a[0].type==X86_OP_REG and a[1].type==X86_OP_MEM and cs.reg_name(a[1].mem.base)=='esi':regs[a[0].reg]={'frame':a[1].mem.disp,'lea':record(i)}
 elif i.mnemonic=='mov' and a[0].type==X86_OP_MEM and cs.reg_name(a[0].mem.base)=='esi' and a[1].type==X86_OP_REG:ptrs[a[0].mem.disp]={**regs[a[1].reg],'store':record(i)}
rows=[]
for slot in range(0x130,0x1c8,8):
 desc=ptrs[slot];name=ptrs[slot+4];n=names.get(name['frame']);field=desc['frame']
 value=int.from_bytes(bytes(mem[field+k] for k in range(4)),'little') if all(field+k in mem for k in range(4)) else None
 rows.append({'name':n['text'] if n else None,'name_evidence':n,'descriptor_frame':hex(field),'descriptor_low_value':hex(value) if value is not None else None,'descriptor_store':stores.get(field),'tuple_offset':hex(slot-0x130),'tuple_descriptor_pointer':desc,'tuple_name_pointer':name})
text=(out/'overlay-field-registration/nl.core.bin.targeted.ghidra.txt').read_text();block=text[text.index('FUNCTION 4188ccd0'):text.index('FUNCTION 41901c60')]
addresses=[int(m[1],16) for m in re.finditer(r'^([0-9a-f]{8}) ',block,re.M)]
kinds={0x41841bd0:'float32',0x4189cb70:'int32',0x418e4310:'raw-pointer'}
dispatch={};pushes=[];loaded={}
for va in addresses:
 i=next(cs.disasm(raw[va-base:va-base+16],va));a=i.operands
 if i.mnemonic=='mov' and len(a)==2 and a[0].type==X86_OP_REG:
  loaded[a[0].reg]=(a[1].mem.disp,record(i)) if a[1].type==X86_OP_MEM and cs.reg_name(a[1].mem.base)=='ebx' else None
 if i.mnemonic=='push':
  value=None
  if a[0].type==X86_OP_MEM and cs.reg_name(a[0].mem.base)=='ebx':value=(a[0].mem.disp,[record(i)])
  elif a[0].type==X86_OP_REG and loaded.get(a[0].reg):
   offset,source=loaded[a[0].reg];value=(offset,[source,record(i)])
  pushes.append(value)
 if i.mnemonic=='call':
  if a[0].type==X86_OP_IMM and a[0].imm in kinds:
   assert len(pushes)>=2 and pushes[-2] and pushes[-1],hex(va)
   desc,name=pushes[-2],pushes[-1];assert name[0]==desc[0]+4
   dispatch[desc[0]]={'kind':kinds[a[0].imm],'registration_helper':hex(a[0].imm),'call':record(i),'argument_instructions':desc[1]+name[1]}
  pushes=[]
  for key in list(loaded):
   if cs.reg_name(key) in ('eax','ecx','edx'):loaded.pop(key)
for row in rows:
 joined=dispatch.get(int(row['tuple_offset'],16))
 if joined:row.update(joined);row['member_offset']=row['descriptor_low_value'];row['direct_setter']='0x4181c310'
 else:row['kind']='special-unverified';row['member_offset']=None
duplicate_names=sorted({r['name'] for r in rows if r['name'] is not None and sum(z['name']==r['name'] for z in rows)>1})
obj={'bulk_call':'0x418c20ef','bulk_helper':'0x4188ccd0','tuple_base':'esi+0x130','rows':rows,'duplicate_names':duplicate_names,'scope':'Tuple/member joins only. Duplicate-name replacement semantics and special callbacks are unresolved.','target_executed':False}
(out/'overlay-field-tuples.json').write_text(json.dumps(obj,indent=2))
table=['# Native animation-layer registration tuples','','Offsets are relative to `C_AnimationLayer`. Special tuples have no asserted member offset. Duplicate-name behavior remains unresolved.','','| Name | Offset | Kind | Registration helper |','|---|---|---|---|']
table+=['| '+('`'+r['name']+'`' if r['name'] else 'not a validated string name')+' | '+(r['member_offset'] or 'unresolved')+' | '+r['kind']+' | '+r.get('registration_helper','inline, unresolved')+' |' for r in rows]
(out/'LAYER_FIELDS.md').write_text('\n'.join(table)+'\n')
print(json.dumps({'tuple_rows':len(rows),'named_tuples':sum(r['name'] is not None for r in rows),'member_joins':len(dispatch),'duplicate_names':duplicate_names}))
