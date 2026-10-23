from legacy_env import research_root, workspace_root, required_path
from pathlib import Path
import ast,ctypes,hashlib,json,struct,sys
root=workspace_root();research=research_root();out=research/'api-index'
out.mkdir(exist_ok=True);ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
# Capstone is installed separately; no private dependency directory is used.
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
from capstone.x86_const import X86_OP_IMM,X86_OP_MEM,X86_OP_REG
data=(research/'ui-controls/nl.core.bin').read_bytes();base=0x412a0000
assert hashlib.sha256(data).hexdigest()=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
cs=Cs(CS_ARCH_X86,CS_MODE_32);cs.detail=True
path=Path(__file__).resolve().parents[1]/'literal_evaluator.py';fn=next(n for n in ast.parse(path.read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='analyze')
exec(compile(ast.Module(body=[fn],type_ignores=[]),str(path),'exec'),globals())
coordinator=list(cs.disasm(data[0x41a18a90-base:0x41a18ae5-base],0x41a18a90))
assert len([i for i in coordinator if i.mnemonic=='call'])==16 and coordinator[-1].mnemonic=='jmp'
targets=[i.operands[0].imm for i in coordinator if i.mnemonic in ['call','jmp']]
results=[]
for target in targets:
 result=analyze(target,data=data,base=base,cs=cs);results.append(result)
 (out/(hex(target)+'.candidates.json')).write_text(json.dumps(result,indent=2))
 names=list(dict.fromkeys(x['text'] for x in result['literals']))
 print(hex(target),','.join(names[:32]),flush=True)
(out/'index.json').write_text(json.dumps({'scope':'Literal candidates only;each binding and native behavior requires independent call-flow checks.','core_sha256':hashlib.sha256(data).hexdigest(),'coordinator':[{ 'va':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str} for i in coordinator],'registrars':[{'entry':r['entry'],'end_exclusive':r['end_exclusive'],'candidate_names':list(dict.fromkeys(x['text'] for x in r['literals']))} for r in results]},indent=2))
