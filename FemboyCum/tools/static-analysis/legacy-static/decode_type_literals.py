from legacy_env import research_root, workspace_root, required_path
from pathlib import Path
import ctypes,hashlib,json,re,sys
root=workspace_root();research=research_root()
ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
# Capstone is installed separately; no private dependency directory is used.
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
from capstone.x86_const import X86_OP_IMM,X86_OP_MEM
raw=(research/'ui-controls/nl.core.bin').read_bytes();base=0x412a0000
assert hashlib.sha256(raw).hexdigest()=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
cs=Cs(CS_ARCH_X86,CS_MODE_32);cs.detail=True;functions={}
assert sys.argv[1:] in ([],['--compound'])
compound=sys.argv[1:]==['--compound']
for area in ['animation-layers','entity-state']:
 for path in (research/area).glob('*/*.targeted.ghidra.txt'):
  for block in re.split(r'(?=^FUNCTION )',path.read_text(),flags=re.M):
   if block.startswith('FUNCTION '):functions[int(block[9:17],16)]=[int(m[1],16) for m in re.finditer(r'^([0-9a-f]{8}) ',block,re.M)]
expected=({0x418df790:'procedural_foot_t',0x41901d60:'procedural_foot_t *',
           0x418eeb20:'aimmatrix_transition_t',0x41901f30:'aimmatrix_transition_t *',
           0x4190a0b0:'animstate_pose_param_cache_t',0x418dd770:'animstate_pose_param_cache_t *',
           0x418e6df0:'int',0x41899700:'int *',0x418e0980:'const int *'} if compound else
          {0x41849b60:'lua::C_GameRulesSafe',0x418504b0:'lua::PlayerResource',0x418f6440:'CCSGOPlayerAnimState *',0x418f7fc0:'CCSGOPlayerAnimState',0x41821a50:'C_AnimationLayer *',0x4184f730:'C_AnimationLayer'})
rows=[]
for entry,type_name in expected.items():
 ins=[next(cs.disasm(raw[a-base:a-base+16],a)) for a in functions[entry]]
 sources=sorted({a.mem.disp for i in ins for a in i.operands if a.type==X86_OP_MEM and 0x42000000<a.mem.disp<0x42100000 and i.mnemonic=='movzx' and a.size==1})
 assert len(sources)==2 and sources[1]==sources[0]+1
 stop=next(i for i in ins if i.mnemonic=='cmp' and i.op_str.startswith('edi, 0x'));last=stop.operands[1].imm
 assert any(i.mnemonic=='mov' and i.op_str=='edi, 5' for i in ins)
 assert any(i.mnemonic=='mov' and i.op_str.endswith('0x539') for i in ins)
 assert sum(i.mnemonic=='imul' and i.operands[-1].type==X86_OP_IMM and i.operands[-1].imm==48271 for i in ins)==2
 start=sources[0]+5;size=last-5+1;seed=1337;decoded=[]
 for value in raw[start-base:start-base+size]:
  decoded.append(value^(seed&255))
  # Exact 32-bit multiply and fast quotient reduction visible in the loop.
  product=seed*48271&0xffffffff;high=product*3>>32
  quotient=(((product-high)>>1)+high)>>30
  assert quotient==product//0x7fffffff
  seed=(product+((quotient<<31)|quotient))&0xffffffff
 text=bytes(decoded).split(b'\0',1)[0].decode('ascii')
 assert text=='std::string sol::detail::ctti_get_type_name() [T = '+type_name+', seperator_mark = int]'
 proof=[i for i in ins if (i.mnemonic=='movzx' and any(a.type==X86_OP_MEM and a.mem.disp in sources for a in i.operands)) or i.mnemonic in ('imul','mul','shr','shl','or') or (i.mnemonic=='mov' and (i.op_str.endswith('0x539') or i.op_str=='edi, 5')) or i.address==stop.address]
 rows.append({'constructor':hex(entry),'ciphertext_va':hex(start),'core_offset':hex(start-base),'ciphertext_size':size,'seed':1337,'key_arithmetic':'32-bit wrapped product by 48271; fast quotient reduction by 0x7fffffff','decoded':text,'native_type':type_name,'selected_instructions':[{'va':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str} for i in proof]})
obj={'scope':'Static type-name literal recovery from constant bytes and integer expressions; no target execution.','core_sha256':hashlib.sha256(raw).hexdigest(),'rows':rows,'target_executed':False}
(research/('entity-state/compound-native-types.json' if compound else 'entity-state/native-types.json')).write_text(json.dumps(obj,indent=2))
print(json.dumps({'decoded_types':[r['native_type'] for r in rows],'target_executed':False}))
