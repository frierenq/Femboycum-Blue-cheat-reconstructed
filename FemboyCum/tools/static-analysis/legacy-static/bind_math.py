from legacy_env import research_root, workspace_root, required_path
from pathlib import Path
import argparse,ctypes,hashlib,json,re,sys
root=workspace_root();research=research_root()
parser=argparse.ArgumentParser(description='Conservative name-object/function-argument joins over saved registrar candidates.')
parser.add_argument('--area',default='value-math');parser.add_argument('registrars',nargs='*')
args=parser.parse_args();assert re.fullmatch(r'[a-z0-9-]+',args.area)
out=research/args.area;out.mkdir(exist_ok=True)
ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
# Capstone is installed separately; no private dependency directory is used.
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
from capstone.x86_const import X86_OP_IMM,X86_OP_MEM
raw=(research/'ui-controls/nl.core.bin').read_bytes();base=0x412a0000
assert hashlib.sha256(raw).hexdigest()=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
cs=Cs(CS_ARCH_X86,CS_MODE_32);cs.detail=True
# These helpers were separately decompiled and shown to consume a string name
# object. Enum-based metamethod helpers may reuse the same frame slots; joining
# a previous string there would invent a method name.
checked_string_helpers={'0x41762d00','0x418289f0',
 # Separately checked in antiaim-accessors/antiaim-string-helpers: param_2
 # is a length/capacity string object used by the Lua name-set operation.
 '0x41950560','0x41a4dda0','0x41a238b0','0x4193d990','0x41914f40'}
result=[]
for entry in args.registrars or ['0x4176e160','0x41759e10']:
 assert re.fullmatch(r'0x[0-9a-f]{8}',entry)
 candidates=json.loads((research/f'api-index/{entry}.candidates.json').read_text());names={}
 start=int(entry,16);end=int(candidates['end_exclusive'],16)
 instructions=list(cs.disasm(raw[start-base:end-base],start))
 for literal in candidates['literals']:
  va=int(literal['at'],16);zero=False
  for ins in list(cs.disasm(raw[va-base:va-base+110],va))[1:]:
   if ins.mnemonic=='xorps' and ins.op_str=='xmm0, xmm0':zero=True
   elif zero and ins.mnemonic=='movaps' and ins.operands[0].type==X86_OP_MEM and cs.reg_name(ins.operands[0].mem.base)=='esi':
    # strlen has one stack argument. Earlier prologue pushes may still be
    # present in the candidate evaluator; the last push is its actual input.
    complete_call=next((c for c in candidates['calls'] if c['target']=='0x42033bb0' and va<int(c['at'],16)<va+140 and c['push_arguments_in_reverse_order'] and isinstance(c['push_arguments_in_reverse_order'][-1],str) and not c['push_arguments_in_reverse_order'][-1].startswith('0x')),None)
    # A final XOR block may contain only a suffix of a longer method name.
    # Accept the full buffer passed to strlen,not that suffix alone.
    if complete_call is None:break
    complete=complete_call['push_arguments_in_reverse_order'][-1]
    names.setdefault(ins.operands[0].mem.disp,[]).append({**literal,'fragment':literal['text'],'text':complete,'full_buffer_strlen_call':complete_call['at']});break
   if ins.mnemonic=='call':break
 # Some names have a different XOR/zeroing schedule. Recover their complete
 # copy only when a matching strlen input and explicit destination agree.
 for call in candidates['calls']:
  ca=call['push_arguments_in_reverse_order'];at=int(call['at'],16)
  if call['target']!='0x4200c9a0' or len(ca)!=3 or not isinstance(ca[1],str) or ca[1].startswith('0x') or not isinstance(ca[2],dict):continue
  off=int(ca[2]['frame_offset'],16)
  if any(0<at-int(n['at'],16)<300 for n in names.get(off,[])):continue
  prior=[c for c in candidates['calls'] if c['target']=='0x42033bb0' and 0<at-int(c['at'],16)<100 and c['push_arguments_in_reverse_order'] and c['push_arguments_in_reverse_order'][-1]==ca[1]]
  if not prior:continue
  names.setdefault(off,[]).append({'at':call['at'],'text':ca[1],'fragment':None,'source_kind':'full_name_copy','full_buffer_strlen_call':prior[-1]['at'],'full_buffer_copy_call':call['at'],'copy_instructions':call['recent_instructions']})
 bindings=[]
 for call in candidates['calls']:
  at=int(call['at'],16);args=call['push_arguments_in_reverse_order']
  if call['target'] not in checked_string_helpers:continue
  if len(args)!=2 or not isinstance(args[1],dict):continue
  direct=isinstance(args[0],str) and args[0].startswith('0x')
  if direct:cb=args[0];slotoff=None
  elif isinstance(args[0],dict):cb=args[0].get('first_dword');slotoff=args[0].get('frame_offset')
  else:continue
  nameoff=args[1].get('frame_offset')
  if not cb or not nameoff or (not direct and not slotoff):continue
  cb=int(cb,16);nameoff=int(nameoff,16);slot=None if direct else int(slotoff,16)
  if not base<=cb<base+len(raw) or nameoff not in names:continue
  prior=[n for n in names[nameoff] if int(n['at'],16)<at]
  if not prior:continue
  name=max(prior,key=lambda n:int(n['at'],16))
  stores=[i for i in instructions if i.address<at and i.mnemonic=='mov' and len(i.operands)==2 and i.operands[0].type==X86_OP_MEM and cs.reg_name(i.operands[0].mem.base)=='esi' and i.operands[0].mem.disp==slot and i.operands[1].type==X86_OP_IMM and i.operands[1].imm==cb]
  if direct:
   if not any(mnem=='push' and ops==hex(cb) for addr,mnem,ops in call['recent_instructions']):continue
  elif not stores:continue
  for addr,mnem,ops in call['recent_instructions']:
   va=int(addr,16);i=next(cs.disasm(raw[va-base:va-base+16],va));assert (i.mnemonic,i.op_str)==(mnem,ops)
  store=None if direct else stores[-1]
  bindings.append({'name':name['text'],'literal_xor':None if name.get('source_kind')=='full_name_copy' else name['at'],'full_buffer_strlen_call':name['full_buffer_strlen_call'],'full_buffer_copy_call':name.get('full_buffer_copy_call'),'name_frame_offset':hex(nameoff),'call':hex(at),'helper':call['target'],'native_target':hex(cb),'slot':None if direct else hex(slot),'slot_store':None if direct else {'va':hex(store.address),'bytes':store.bytes.hex(),'instruction':store.mnemonic+' '+store.op_str},'registration_instructions':call['recent_instructions'],'scope':'Checked function/name arguments;target body and public signature require separate validation.'})
 result.append({'registrar':entry,'bindings':bindings,'name_objects':[{'frame_offset':hex(k),**n} for k,values in names.items() for n in values],'unjoined_literal_candidates':[n['text'] for n in candidates['literals'] if n['text'] not in {b['name'] for b in bindings}]})
 print(entry,[(b['name'],b['native_target']) for b in bindings],flush=True)
(out/'named-bindings.json').write_text(json.dumps(result,indent=2))
