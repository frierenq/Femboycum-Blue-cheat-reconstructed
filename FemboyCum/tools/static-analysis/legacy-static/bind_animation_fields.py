from legacy_env import research_root, workspace_root, required_path
from pathlib import Path
import ctypes,hashlib,json,re,sys
root=workspace_root();research=research_root();out=research/'entity-state'
ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
# Capstone is installed separately; no private dependency directory is used.
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
from capstone.x86_const import X86_OP_IMM,X86_OP_MEM,X86_OP_REG
raw=(research/'ui-controls/nl.core.bin').read_bytes();base=0x412a0000
assert hashlib.sha256(raw).hexdigest()=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
cs=Cs(CS_ARCH_X86,CS_MODE_32);cs.detail=True
names={int(x['frame_offset'],16):x for x in json.loads((out/'named-bindings.json').read_text())[0]['name_objects'] if 0x418b0000<int(x['at'],16)<0x418bdafa}
mem={};stores={};ptrs={};regs={}
def instruction(i):return {'va':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str}
for i in cs.disasm(raw[0x418a5770-base:0x418bdb2e-base],0x418a5770):
 a=i.operands
 if i.mnemonic=='mov' and len(a)==2 and a[0].type==X86_OP_MEM and cs.reg_name(a[0].mem.base)=='esi' and a[1].type==X86_OP_IMM:
  n=a[0].size;off=a[0].mem.disp;v=a[1].imm&((1<<(n*8))-1)
  for k,c in enumerate(v.to_bytes(n,'little')):mem[off+k]=c;stores[off+k]=instruction(i)
for i in cs.disasm(raw[0x418bdb2e-base:0x418be4ca-base],0x418bdb2e):
 a=i.operands
 if i.mnemonic=='lea' and a[0].type==X86_OP_REG and a[1].type==X86_OP_MEM and cs.reg_name(a[1].mem.base)=='esi':regs[a[0].reg]={'frame':a[1].mem.disp,'lea':instruction(i)}
 elif i.mnemonic=='mov' and a[0].type==X86_OP_MEM and cs.reg_name(a[0].mem.base)=='esi' and a[1].type==X86_OP_REG:
  ptrs[a[0].mem.disp]={**regs[a[1].reg],'store':instruction(i)}
rows=[]
for slot in range(0x140,0x458,8):
 desc=ptrs[slot];name=ptrs[slot+4];n=names[name['frame']];field=desc['frame'];size=4 if all(field+k in mem for k in range(4)) else (1 if field in mem else 0)
 value=int.from_bytes(bytes(mem[field+k] for k in range(size)),'little') if size else None
 rows.append({'name':n['text'],'name_frame':hex(name['frame']),'name_evidence':n,'descriptor_frame':hex(field),'descriptor_low_value':hex(value) if value is not None else None,'descriptor_bytes':size,'descriptor_store':stores.get(field),'tuple_offset':hex(slot-0x130),'tuple_descriptor_pointer':desc,'tuple_name_pointer':name,'scope':'Tuple plus descriptor initializer. A member offset is asserted only after joining a consuming member-registration helper. Missing immediate initializers stay unknown.'})

# These functions register member descriptors. Scalar getter and readonly
# setter bodies are checked separately; compound getter lifetimes remain open.
kinds={0x41858da0:'float32',0x418974f0:'int32',0x418eb9f0:'bool8',0x418df180:'vector3-reference',0x4184c6c0:'compound-unverified',0x418f7ec0:'compound-unverified',0x4190ed00:'pose-map-unverified',0x418ebe70:'preset-unverified'}
text=(out/'animation-userdata/nl.core.bin.targeted.ghidra.txt').read_text();block=text[text.index('FUNCTION 41878620'):text.index('FUNCTION 41852300')]
addresses=[int(m[1],16) for m in re.finditer(r'^([0-9a-f]{8}) ',block,re.M)]
dispatch={};pushes=[];loaded={}
for va in addresses:
 i=next(cs.disasm(raw[va-base:va-base+16],va));a=i.operands
 if i.mnemonic=='mov' and len(a)==2 and a[0].type==X86_OP_REG:
  loaded[a[0].reg]=(a[1].mem.disp,instruction(i)) if a[1].type==X86_OP_MEM and cs.reg_name(a[1].mem.base)=='ebx' else None
 if i.mnemonic=='push':
  value=None
  if a[0].type==X86_OP_MEM and cs.reg_name(a[0].mem.base)=='ebx':value=(a[0].mem.disp,[instruction(i)])
  elif a[0].type==X86_OP_REG and loaded.get(a[0].reg):
   off,source=loaded[a[0].reg];value=(off,[source,instruction(i)])
  pushes.append(value)
 if i.mnemonic=='call':
  if a[0].type==X86_OP_IMM and a[0].imm in kinds:
   assert len(pushes)>=2 and pushes[-1] and pushes[-2],hex(va)
   desc,name=pushes[-2],pushes[-1]
   assert name[0]==desc[0]+4 and desc[0] not in dispatch,(hex(va),desc,name)
   dispatch[desc[0]]={'kind':kinds[a[0].imm],'registration_helper':hex(a[0].imm),'call':instruction(i),'argument_instructions':desc[1]+name[1]}
  pushes=[]
  for key in list(loaded):
   if cs.reg_name(key) in ('eax','ecx','edx'):loaded.pop(key)
for row in rows:
 d=dispatch.get(int(row['tuple_offset'],16))
 if d:row.update(d);row['member_offset']=row['descriptor_low_value'];row['readonly_setter']='0x4181c310' if d['kind'] in ('float32','int32','bool8','vector3-reference') else None
 else:row['kind']='special-property-unverified';row['member_offset']=None
obj={'bulk_call':'0x418be4ca','bulk_helper':'0x41878620','tuple_base':'esi+0x130','rows':rows,'target_executed':False,'scope':'Static field layout and registration map, not animation update or resolver source.'}
(out/'animation-field-tuples.json').write_text(json.dumps(obj,indent=2))
counts={k:sum(x['kind']==k for x in rows) for k in sorted({x['kind'] for x in rows})}
table=['# Animation-state field map','', 'Generated by `bind_animation_fields.py` from this FemboyLose core. Offsets are relative to the native animation-state object. Unknown compound semantics and special properties are explicitly marked. No live process was read.','', '| Name | Offset | Native kind | Registration helper |','|---|---|---|---|']
table+=['| `'+x['name']+'` | '+('`'+x['member_offset']+'`' if x['member_offset'] else 'special, unresolved')+' | '+x['kind']+' | '+x.get('registration_helper','inline, unresolved')+' |' for x in rows]
(out/'ANIMATION_FIELDS.md').write_text('\n'.join(table)+'\n')
print(json.dumps({'tuple_rows':len(rows),'member_registration_joins':len(dispatch),'kinds':counts}))
