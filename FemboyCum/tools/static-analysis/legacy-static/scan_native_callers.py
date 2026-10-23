from legacy_env import research_root, workspace_root, required_path
from pathlib import Path
import ctypes,hashlib,json,struct
root=workspace_root();research=research_root()
ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
raw=(research/'ui-controls/nl.core.bin').read_bytes();base=0x412a0000
assert hashlib.sha256(raw).hexdigest()=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
targets={0x41b70930:[],0x41b73970:[],0x41b6d100:[]};pos=0
while True:
 pos=raw.find(b'\xe8',pos)
 if pos<0 or pos+5>len(raw):break
 target=(base+pos+5+struct.unpack_from('<i',raw,pos+1)[0])&0xffffffff
 if target in targets and base+pos<0x42050000:
  entry=None
  for q in range(pos&~15,max(0,pos-0x2000),-16):
   if raw[q-1:q]==b'\xcc' and raw[q:q+1] in [b'\x55',b'\x53',b'\x56',b'\x57',b'\x83',b'\x81',b'\x50',b'\x8b',b'\xa1']:
    entry=base+q;break
  targets[target].append({'call':hex(base+pos),'bytes':raw[pos:pos+5].hex(),'candidate_entry':hex(entry) if entry else None})
 pos+=1
out=research/'native-consumers';out.mkdir(exist_ok=True)
obj={'scope':'Byte-pattern direct-call leads. Caller entry and control flow must be validated separately.','targets':{hex(k):v for k,v in targets.items()},'target_executed':False}
(out/'direct-call-leads.json').write_text(json.dumps(obj,indent=2))
print(json.dumps({'direct_call_leads':{hex(k):len(v) for k,v in targets.items()},'target_executed':False}))
