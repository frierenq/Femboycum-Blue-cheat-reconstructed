"""Narrow candidate scan: straight-line register constants on exported boundaries.

This is intentionally a lead index. Branch merging, stack aliasing, indirect
memory and full original code coverage are not proved.
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

import hashlib,json,re,sys
root=Path(os.environ["FC_RESEARCH_ROOT"])
binary=Path(os.environ["FC_RESEARCH_CORE"])
raw=binary.read_bytes();sha=hashlib.sha256(raw).hexdigest()
assert sha=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
sys.path.insert(0,str(Path(os.environ["FC_RESEARCH_PYTHON_LIBS"])))
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
from capstone.x86_const import X86_OP_REG,X86_OP_IMM,X86_OP_MEM
cs=Cs(CS_ARCH_X86,CS_MODE_32);cs.detail=True
base=0x412a0000;target=0x415debd0
source=Path(os.environ["FC_RESEARCH_AUX_INPUT_DIR"])
records=[];matches=[];count=0
mask=0xffffffff
def rotl(v,n):return ((v<<n)|(v>>(32-n)))&mask if n else v
def rotr(v,n):return ((v>>n)|(v<<(32-n)))&mask if n else v
for path in sorted(source.glob('*/*.targeted.ghidra.txt')):
    for block in re.split(r'(?=^FUNCTION )',path.read_text(encoding='utf-8'),flags=re.M):
        if not block.startswith('FUNCTION '):continue
        entry=int(block[9:17],16);regs={};last=None
        for m in re.finditer(r'^([0-9a-f]{8}) ',block,re.M):
            va=int(m[1],16)
            i=next(cs.disasm(raw[va-base:va-base+15],va,count=1),None)
            if i is None:continue
            count+=1
            if last is not None and va!=last:
                regs.clear()
            last=va+i.size
            ops=i.operands
            before=dict(regs)
            def value(op):
                if op.type==X86_OP_IMM:return op.imm&mask
                if op.type==X86_OP_REG:return regs.get(cs.reg_name(op.reg))
                return None
            if i.mnemonic=='mov' and len(ops)==2 and ops[0].type==X86_OP_REG:
                regs[cs.reg_name(ops[0].reg)]=value(ops[1])
            elif i.mnemonic=='lea' and len(ops)==2 and ops[0].type==X86_OP_REG:
                d=ops[1].mem
                x=regs.get(cs.reg_name(d.base)) if d.base else 0
                y=regs.get(cs.reg_name(d.index)) if d.index else 0
                regs[cs.reg_name(ops[0].reg)]=(x+y*d.scale+d.disp)&mask if x is not None and y is not None else None
            elif i.mnemonic=='xor' and len(ops)==2 and ops[0].type==X86_OP_REG and ops[1].type==X86_OP_REG and ops[0].reg==ops[1].reg:
                regs[cs.reg_name(ops[0].reg)]=0
            elif i.mnemonic in ('add','sub','xor','and','or') and len(ops)==2 and ops[0].type==X86_OP_REG:
                name=cs.reg_name(ops[0].reg);x=regs.get(name);y=value(ops[1])
                if x is not None and y is not None:
                    regs[name]={'add':lambda:x+y,'sub':lambda:x-y,'xor':lambda:x^y,'and':lambda:x&y,'or':lambda:x|y}[i.mnemonic]()&mask
                else:regs[name]=None
            elif i.mnemonic in ('rol','ror') and len(ops)==2 and ops[0].type==X86_OP_REG:
                name=cs.reg_name(ops[0].reg);x=regs.get(name);y=value(ops[1])
                regs[name]=(rotl(x,y&31) if i.mnemonic=='rol' else rotr(x,y&31)) if x is not None and y is not None else None
            elif i.mnemonic=='not' and len(ops)==1 and ops[0].type==X86_OP_REG:
                name=cs.reg_name(ops[0].reg);x=regs.get(name);regs[name]=(~x)&mask if x is not None else None
            elif i.mnemonic=='call':
                for name in ('eax','ecx','edx'):regs[name]=None
            elif ops and ops[0].type==X86_OP_REG and not (i.mnemonic.startswith('j') or i.mnemonic in ('cmp','test','push','bt','ucomiss','comiss')):
                regs[cs.reg_name(ops[0].reg)]=None
            for name,val in regs.items():
                if val==target and before.get(name)!=target:
                    matches.append({'va':hex(va),'function':hex(entry),'register':name,'instruction':i.mnemonic+' '+i.op_str,'source':str(path.relative_to(source))})
            if i.mnemonic.startswith('ret'):regs.clear()
report={'core_sha256':sha,'target':hex(target),'export_instruction_boundaries_scanned':count,'scope':'Linear constant propagation over exported contiguous instruction starts. Candidate values need CFG and argument-use corroboration; absent match is not a whole-image negative result.','matches':matches}
_fc_output('computed-pointer-leads.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'boundaries_scanned':count,'matches':matches},indent=2))
