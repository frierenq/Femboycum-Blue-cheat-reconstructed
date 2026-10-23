"""Candidate-only scan for locally calculated reset pointer in mapped code bytes.

Starts at every raw B8..BF byte (including false instruction starts), decodes
up to 20 following instructions, and folds only same-register 32-bit scalar
operations. Every match needs independent instruction-boundary/CFG proof.
"""
import sys
sys.dont_write_bytecode = True
if not __debug__: raise RuntimeError("Python -O disables assertions")

import os
from pathlib import Path

def _fc_output_root():
    value = os.environ.get("FC_RESEARCH_OUTPUT_DIR")
    if not value or not Path(value).is_absolute():
        raise RuntimeError("set FC_RESEARCH_OUTPUT_DIR to an absolute scratch directory")
    root = Path(value).resolve(strict=True)
    if not root.is_dir():
        raise RuntimeError("FC_RESEARCH_OUTPUT_DIR must be an existing directory")
    public_tree = Path(__file__).resolve().parents[3]
    if root == public_tree or root.is_relative_to(public_tree):
        raise RuntimeError("research output cannot be inside the source candidate/public tools tree")
    if public_tree.name == "research-tools" and root.is_relative_to(public_tree.parent):
        raise RuntimeError("research output cannot be inside the public release tree")
    return root


def _fc_output(name):
    root = _fc_output_root()
    target = (root / name).resolve()
    if not target.is_relative_to(root):
        raise RuntimeError("research output path escapes scratch directory")
    return target


def _fc_checked_output(path):
    target = Path(path).resolve()
    if not target.is_relative_to(_fc_output_root()):
        raise RuntimeError("explicit output must be inside FC_RESEARCH_OUTPUT_DIR")
    return target

import ctypes,hashlib,json,sys
root=Path(os.environ["FC_RESEARCH_ROOT"])
binary=Path(os.environ["FC_RESEARCH_CORE"])
raw=binary.read_bytes();sha=hashlib.sha256(raw).hexdigest()
assert sha=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
sys.path.insert(0,str(Path(os.environ["FC_RESEARCH_PYTHON_LIBS"])))
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
from capstone.x86_const import X86_OP_REG,X86_OP_IMM
cs=Cs(CS_ARCH_X86,CS_MODE_32);cs.detail=True
base=0x412a0000;end=0x42040000;target=0x415debd0;mask=0xffffffff
region=raw[:end-base];hits=[];candidates=0;decoded_windows=0
for offset,byte in enumerate(region[:-5]):
    if not 0xb8<=byte<=0xbf:continue
    va=base+offset
    first=next(cs.disasm(region[offset:offset+15],va,count=1),None)
    if first is None or first.mnemonic!='mov' or len(first.operands)!=2 or first.operands[0].type!=X86_OP_REG or first.operands[1].type!=X86_OP_IMM or first.operands[0].size!=4:continue
    candidates+=1
    reg=first.operands[0].reg;value=first.operands[1].imm&mask
    trace=[{'va':hex(va),'bytes':first.bytes.hex(),'instruction':first.mnemonic+' '+first.op_str,'value':hex(value)}]
    cursor=offset+first.size
    for _ in range(20):
        if value==target:
            hits.append({'start':hex(va),'end':trace[-1]['va'],'register':cs.reg_name(reg),'trace':trace.copy()})
            break
        i=next(cs.disasm(region[cursor:cursor+15],base+cursor,count=1),None)
        if i is None:break
        decoded_windows+=1
        ops=i.operands;mn=i.mnemonic
        if mn=='nop' or mn.startswith('nop'):
            pass
        elif mn in ('add','sub','xor','and','or','rol','ror','shl','shr','sar','imul') and len(ops)>=2 and ops[0].type==X86_OP_REG and ops[0].reg==reg and ops[1].type==X86_OP_IMM:
            n=ops[1].imm&mask
            if mn=='add':value=(value+n)&mask
            elif mn=='sub':value=(value-n)&mask
            elif mn=='xor':value^=n
            elif mn=='and':value&=n
            elif mn=='or':value|=n
            elif mn=='rol':value=((value<<(n&31))|(value>>(32-(n&31))))&mask if n&31 else value
            elif mn=='ror':value=((value>>(n&31))|(value<<(32-(n&31))))&mask if n&31 else value
            elif mn=='shl':value=(value<<(n&31))&mask
            elif mn=='shr':value>>=(n&31)
            elif mn=='sar':value=((value^0x80000000)-0x80000000)>>(n&31)&mask
            elif mn=='imul' and len(ops)==3 and ops[1].type==X86_OP_REG and ops[1].reg==reg and ops[2].type==X86_OP_IMM:value=(value*(ops[2].imm&mask))&mask
            elif mn=='imul':break
        elif mn=='jmp' and len(ops)==1 and ops[0].type==X86_OP_IMM and (ops[0].imm&mask)==base+cursor+i.size:
            pass
        elif mn.startswith('j') or mn.startswith('ret') or mn=='call':break
        elif any(op.type==X86_OP_REG and op.reg==reg for op in ops[:1]):break
        trace.append({'va':hex(i.address),'bytes':i.bytes.hex(),'instruction':mn+' '+i.op_str,'value':hex(value)})
        cursor+=i.size
report={'core_sha256':sha,'code_region':[hex(base),hex(end)],'target':hex(target),
        'scope':'Raw candidate windows at every B8..BF byte in mapped code range; false instruction starts and unreachable paths are expected. No absence or reachability proof.',
        'starts':candidates,'subsequent_instructions_decoded':decoded_windows,'hits':hits}
_fc_output('code-constant-window-leads.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'starts':candidates,'decoded':decoded_windows,'hits':hits[:20],'hit_count':len(hits)},indent=2))
