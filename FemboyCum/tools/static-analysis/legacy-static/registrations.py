from legacy_env import research_root, workspace_root, required_path
"""Re-evaluate native group registrations from FemboyLose's copied core."""
from pathlib import Path
import ast,ctypes,hashlib,json,struct,sys
root=workspace_root();out=research_root()/'ui-controls'
ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
# Capstone is installed separately; no private dependency directory is used.
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
from capstone.x86_const import X86_OP_IMM,X86_OP_MEM,X86_OP_REG
data=(out/'nl.core.bin').read_bytes();base=0x412a0000
assert hashlib.sha256(data).hexdigest()=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
cs=Cs(CS_ARCH_X86,CS_MODE_32);cs.detail=True
# Reuse only the previously authored bounded constant-expression evaluator.
# No old project is run or changed;all input/output belongs to FemboyLose.
tool=Path(__file__).resolve().parents[1]/'literal_evaluator.py'
tree=ast.parse(tool.read_text());fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='analyze')
exec(compile(ast.Module(body=[fn],type_ignores=[]),str(tool),'exec'),globals())
result=analyze(0x41aae970,data=data,base=base,cs=cs)
(out/'registration-candidates.json').write_text(json.dumps(result,indent=2))
names={}
for literal in result['literals']:
 va=int(literal['at'],16);zero=False
 for ins in list(cs.disasm(data[va-base:va-base+110],va))[1:]:
  if ins.mnemonic=='xorps' and ins.op_str=='xmm0, xmm0':zero=True
  elif zero and ins.mnemonic=='movaps' and ins.operands[0].type==X86_OP_MEM and cs.reg_name(ins.operands[0].mem.base)=='esi':
   names.setdefault(ins.operands[0].mem.disp,[]).append(literal);break
  if ins.mnemonic=='call':break
instructions=list(cs.disasm(data[0x41aae970-base:int(result['end_exclusive'],16)-base],0x41aae970))
bindings=[]
for call in result['calls']:
 at=int(call['at'],16);args=call['push_arguments_in_reverse_order']
 if not 0x41ab4c00<=at<0x41ab4e80:continue
 if len(args)!=2 or not all(isinstance(a,dict) for a in args):continue
 cb=args[0].get('first_dword');nameoff=args[1].get('frame_offset')
 if not cb or not nameoff or int(nameoff,16) not in names:continue
 matches=[n for n in names[int(nameoff,16)] if int(n['at'],16)<at]
 if not matches:continue
 name=max(matches,key=lambda n:int(n['at'],16))
 slot=int(args[0]['frame_offset'],16);callback=int(cb,16)
 stores=[i for i in instructions if i.address<at and i.mnemonic=='mov' and len(i.operands)==2 and i.operands[0].type==X86_OP_MEM and cs.reg_name(i.operands[0].mem.base)=='esi' and i.operands[0].mem.disp==slot and i.operands[1].type==X86_OP_IMM and i.operands[1].imm==callback]
 assert stores,(name['text'],cb)
 store=stores[-1]
 # Independently re-decode every recorded instruction at the registration site.
 for addr,mnemonic,operands in call['recent_instructions']:
  va=int(addr,16);ins=next(cs.disasm(data[va-base:va-base+16],va))
  assert (ins.mnemonic,ins.op_str)==(mnemonic,operands)
 bindings.append({'name':name['text'],'literal_xor':name['at'],'name_frame_offset':nameoff,'registration_call':call['at'],'registration_helper':call['target'],'member_target':cb,'member_slot':hex(slot),'member_store':{'va':hex(store.address),'bytes':store.bytes.hex(),'instruction':store.mnemonic+' '+store.op_str},'registration_instructions':call['recent_instructions'],'scope':'Name and function-pointer binding,not full method signature or functionality.'})
assert {b['name'] for b in bindings}>={'switch','slider','combo','selectable','input','button'}
(out/'group-bindings.json').write_text(json.dumps(bindings,indent=2))
for binding in bindings:print(binding['name'],binding['member_target'],binding['registration_call'])
