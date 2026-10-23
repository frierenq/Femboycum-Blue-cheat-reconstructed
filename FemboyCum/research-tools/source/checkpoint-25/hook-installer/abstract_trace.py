"""Static abstract interpretation of decoded nl.core.bin instructions.

This reads pinned bytes as data. It neither loads nor executes the binary.
Only local, explicitly implemented x86 semantics are interpreted.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True
if not __debug__: raise RuntimeError("Python -O disables assertions")

import os
from dataclasses import dataclass
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

import hashlib
import json
import struct
import sys

TH = Path(os.environ["FC_RESEARCH_ROOT"])
CORE = Path(os.environ["FC_RESEARCH_CORE"])
RAW = CORE.read_bytes()
SHA = '682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
assert hashlib.sha256(RAW).hexdigest() == SHA
BASE = 0x412a0000
END = BASE + len(RAW)
sys.path.insert(0, str(Path(os.environ["FC_RESEARCH_PYTHON_LIBS"])))
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM

CS = Cs(CS_ARCH_X86, CS_MODE_32)
CS.detail = True
MASK = 0xffffffff

@dataclass(frozen=True)
class Ptr:
    base: str
    off: int = 0
    def __post_init__(self):
        # x86 effective addresses wrap modulo 2^32. Keep affine offsets in
        # signed canonical form so large displacement/index terms can cancel.
        object.__setattr__(self, 'off', ((self.off + 0x80000000) & MASK) - 0x80000000)
    def __str__(self):
        return f'{self.base}{self.off:+#x}'

@dataclass(frozen=True)
class Unknown:
    why: str
    def __str__(self):
        return f'?({self.why})'

@dataclass(frozen=True)
class FlagWord:
    status: tuple

@dataclass(frozen=True)
class Piece:
    source: object
    shift: int

def U(x): return x & MASK
def signed(x,bits):
    x &= (1<<bits)-1
    return x-(1<<bits) if x & (1<<(bits-1)) else x
def parity(x): return int(((x&255).bit_count() & 1)==0)
def known(x): return isinstance(x,int)

REGS = {}
for stem in 'abcd':
    full=f'e{stem}x'
    REGS[full]=(full,0,32)
    REGS[f'{stem}x']=(full,0,16)
    REGS[f'{stem}l']=(full,0,8)
    REGS[f'{stem}h']=(full,8,8)
for full,short in [('esi','si'),('edi','di'),('esp','sp'),('ebp','bp')]:
    REGS[full]=(full,0,32)
    REGS[short]=(full,0,16)

class Machine:
    def __init__(self, continue_cpuid=False, instruction_limit=12000, byte_read_limit=8192):
        self.reg={k:Unknown('incoming '+k) for k in ('eax','ebx','ecx','edx','esi','edi','esp','ebp')}
        self.reg['esp']=Ptr('S',0)
        self.flags={k:None for k in ('CF','ZF','SF','PF','OF')}
        self.mem={}
        self.pc=0x41da0ba0
        self.current_ins=self.pc
        self.steps=0
        self.edges=[]
        self.loads=[]
        self.unresolved_reads=[]
        self.events=[]
        self.stop=None
        self.byte_reads=0
        self.continue_cpuid=continue_cpuid
        self.instruction_limit=instruction_limit
        self.byte_read_limit=byte_read_limit
        self.store(Ptr('S',0),4,Unknown('publisher return'))
        self.store(Ptr('S',4),4,1)
        self.store(Ptr('S',8),4,Ptr('D',0))
        # The publisher's output word is stack-local, but its exact offset
        # relative to installer-entry S is not yet proved. Keep its pointer
        # unresolved so a future dereference cannot hide a possible S alias.
        for off,val in [(0,0x28526880),(4,0),(8,0x415a6b20),(12,0),
                        (16,Unknown('caller stack output pointer/delta')),(20,0)]:
            self.store(Ptr('D',off),4,val)
        self.events.clear()

    def getreg(self,name):
        if name not in REGS: return Unknown('register '+name)
        full,shift,bits=REGS[name]
        val=self.reg[full]
        if bits==32: return val
        if known(val): return (val>>shift)&((1<<bits)-1)
        if isinstance(val,Ptr):
            return Unknown('partial pointer '+name)
        return Unknown('partial '+name+' of '+str(val))

    def setreg(self,name,val):
        if name not in REGS: raise RuntimeError('unknown register '+name)
        full,shift,bits=REGS[name]
        if known(val): val &= (1<<bits)-1
        if bits==32: self.reg[full]=val; return
        old=self.reg[full]
        if known(old) and known(val):
            mask=((1<<bits)-1)<<shift
            self.reg[full]=U((old&~mask)|(val<<shift))
        else:
            self.reg[full]=Unknown('partial write '+name)

    def addr_add(self,a,b):
        if known(a) and known(b): return U(a+b)
        if isinstance(a,Ptr) and known(b): return Ptr(a.base,a.off+signed(b,32))
        if known(a) and isinstance(b,Ptr): return Ptr(b.base,b.off+signed(a,32))
        return Unknown('address arithmetic')

    def address(self,op):
        mm=op.mem
        parts=[]
        for r,scale in ((mm.base,1),(mm.index,mm.scale)):
            if not r: continue
            v=self.getreg(CS.reg_name(r))
            if scale!=1:
                v=U(v*scale) if known(v) else Unknown('scaled symbolic index')
            parts.append(v)
        v=U(mm.disp)
        for p in parts: v=self.addr_add(v,p)
        return v

    def _memkey(self,addr,i):
        if isinstance(addr,Ptr): return (addr.base,Ptr(addr.base,addr.off+i).off)
        return None

    def store(self,addr,n,val):
        if isinstance(addr,Ptr) and addr.base=='D' and not (0<=addr.off and addr.off+n<=24):
            raise RuntimeError(f'write outside 24-byte descriptor fixture {addr} size {n}')
        if isinstance(addr,Ptr) and addr.base in ('S','D'):
            if addr.base=='D': self.events.append(f'write descriptor {addr} <- {val}')
            for i in range(n):
                self.mem[self._memkey(addr,i)]=((val>>(8*i))&255) if known(val) else Piece(val,8*i)
            return
        raise RuntimeError(f'unknown/external write {addr} size {n} value {val}')

    def load(self,addr,n):
        if isinstance(addr,Ptr) and addr.base=='D' and not (0<=addr.off and addr.off+n<=24):
            raise RuntimeError(f'read outside 24-byte descriptor fixture {addr} size {n}')
        if isinstance(addr,Ptr) and addr.base in ('S','D'):
            cells=[self.mem.get(self._memkey(addr,i)) for i in range(n)]
            if any(c is None for c in cells):
                self.unresolved_reads.append({'pc':f'{self.current_ins:08x}','address':str(addr),'size':n,'kind':'uninitialized symbolic stack/object byte'})
                raise RuntimeError(f'unresolved live stack/object byte at {self.current_ins:#x}: {addr} width {n}')
            if addr.base=='D' or (addr.base=='S' and addr.off>=0):
                self.loads.append({'pc':f'{self.current_ins:08x}','address':str(addr),'size':n})
            if all(known(c) for c in cells):
                return sum(c<<(8*i) for i,c in enumerate(cells))
            # A partial byte/word load cannot reconstruct a saved 32-bit
            # symbolic pointer, register, or flags word as the full value.
            if n==4 and all(isinstance(c,Piece) for c in cells):
                src=cells[0].source
                if all(c.source==src and c.shift==8*i for i,c in enumerate(cells)):
                    return src
            return Unknown(f'partial/unknown {addr} width {n}')
        if known(addr):
            if BASE<=addr and addr+n<=END:
                self.byte_reads+=n
                if self.byte_reads>self.byte_read_limit: raise RuntimeError('core byte-read limit')
                return int.from_bytes(RAW[addr-BASE:addr-BASE+n],'little')
            self.unresolved_reads.append({'pc':f'{self.current_ins:08x}','address':f'{addr:08x}','size':n,'kind':'external live memory'})
            return Unknown(f'external read {addr:#x} width {n}')
        self.unresolved_reads.append({'pc':f'{self.current_ins:08x}','address':str(addr),'size':n,'kind':'unknown pointer'})
        return Unknown(f'unknown read {addr} width {n}')

    def value(self,op):
        if op.type==X86_OP_IMM: return U(op.imm)
        if op.type==X86_OP_REG: return self.getreg(CS.reg_name(op.reg))
        if op.type==X86_OP_MEM: return self.load(self.address(op),op.size)
        raise RuntimeError('operand type '+str(op.type))

    def write(self,op,val):
        if op.type==X86_OP_REG: return self.setreg(CS.reg_name(op.reg),val)
        if op.type==X86_OP_MEM: return self.store(self.address(op),op.size,val)
        raise RuntimeError('write operand type '+str(op.type))

    def push(self,val):
        sp=self.reg['esp']
        if not isinstance(sp,Ptr) or sp.base!='S': raise RuntimeError('unknown ESP '+str(sp))
        sp=Ptr('S',sp.off-4)
        self.reg['esp']=sp
        self.store(sp,4,val)

    def pop(self):
        sp=self.reg['esp']
        if not isinstance(sp,Ptr) or sp.base!='S': raise RuntimeError('unknown ESP '+str(sp))
        val=self.load(sp,4)
        self.reg['esp']=Ptr('S',sp.off+4)
        return val

    def setresult(self,res,bits,cf=None,of=None,preserve_cf=False):
        if not preserve_cf: self.flags['CF']=cf
        self.flags['OF']=of
        if known(res):
            res&=(1<<bits)-1
            self.flags['ZF']=int(res==0)
            self.flags['SF']=(res>>(bits-1))&1
            self.flags['PF']=parity(res)
        else:
            self.flags['ZF']=self.flags['SF']=self.flags['PF']=None

    def binary(self,kind,a,b,bits):
        mask=(1<<bits)-1
        cin=self.flags['CF'] if kind in ('adc','sbb') else 0
        if kind in ('adc','sbb') and cin is None: return Unknown('carry input'),None,None
        if kind=='and':
            if (known(a) and (a&mask)==0) or (known(b) and (b&mask)==0): return 0,0,0
            if known(b) and (b&mask)==mask: return a,0,0
            if known(a) and (a&mask)==mask: return b,0,0
        if kind=='or':
            if known(b) and (b&mask)==mask or known(a) and (a&mask)==mask: return mask,0,0
            if known(b) and (b&mask)==0: return a,0,0
            if known(a) and (a&mask)==0: return b,0,0
        if kind=='xor':
            if known(b) and (b&mask)==0: return a,0,0
            if known(a) and (a&mask)==0: return b,0,0
        if isinstance(a,Ptr) and known(b) and kind in ('add','sub','adc','sbb'):
            delta=signed(b,bits)+(cin or 0)
            if kind in ('sub','sbb'): delta=-delta
            return Ptr(a.base,a.off+delta),None,None
        if known(a) and isinstance(b,Ptr) and kind in ('add','adc'):
            return Ptr(b.base,b.off+signed(a,bits)+(cin or 0)),None,None
        if isinstance(a,Ptr) and isinstance(b,Ptr) and a.base==b.base and kind=='sub':
            # Same stack base; requires that the finite stack offsets have not
            # crossed the 32-bit address-space wrap boundary. Signed OF also
            # depends on the unknown numeric base crossing the sign boundary.
            return U(a.off-b.off),int(a.off<b.off),None
        if not (known(a) and known(b)): return Unknown(kind+' symbolic'),None,None
        a&=mask; b&=mask
        if kind in ('and','or','xor'):
            r={'and':a&b,'or':a|b,'xor':a^b}[kind]
            return r,0,0
        if kind in ('add','adc'):
            full=a+b+(cin or 0); r=full&mask
            cf=int(full>mask)
            of=int(((~(a^b))&(a^r)&(1<<(bits-1)))!=0)
            return r,cf,of
        if kind in ('sub','sbb'):
            rhs=b+(cin or 0); full=a-rhs; r=full&mask
            cf=int(full<0)
            of=int((((a^b)&(a^r))&(1<<(bits-1)))!=0)
            return r,cf,of
        raise RuntimeError('binary '+kind)

    def condition(self,mn):
        f=self.flags
        if mn in ('je','jz'): return f['ZF']==1 if f['ZF'] is not None else None
        if mn in ('jne','jnz'): return f['ZF']==0 if f['ZF'] is not None else None
        if mn in ('ja','jnbe'):
            if f['CF']==1 or f['ZF']==1: return False
            if f['CF']==0 and f['ZF']==0: return True
            return None
        if mn in ('jae','jnb','jnc'): return (f['CF']==0) if f['CF'] is not None else None
        if mn in ('jb','jc','jnae'): return (f['CF']==1) if f['CF'] is not None else None
        if mn in ('jbe','jna'):
            if f['CF']==1 or f['ZF']==1: return True
            if f['CF']==0 and f['ZF']==0: return False
            return None
        if mn in ('jl','jnge'): return (f['SF']!=f['OF']) if f['SF'] is not None and f['OF'] is not None else None
        if mn in ('jge','jnl'): return (f['SF']==f['OF']) if f['SF'] is not None and f['OF'] is not None else None
        if mn in ('jle','jng'):
            if f['ZF']==1: return True
            if f['ZF']==0 and f['SF'] is not None and f['OF'] is not None: return f['SF']!=f['OF']
            return None
        if mn in ('jg','jnle'):
            if f['ZF']==1: return False
            if f['ZF']==0 and f['SF'] is not None and f['OF'] is not None: return f['SF']==f['OF']
            return None
        if mn in ('jp','jpe'): return (f['PF']==1) if f['PF'] is not None else None
        if mn in ('jnp','jpo'): return (f['PF']==0) if f['PF'] is not None else None
        if mn in ('js',): return (f['SF']==1) if f['SF'] is not None else None
        if mn in ('jns',): return (f['SF']==0) if f['SF'] is not None else None
        if mn in ('jo',): return (f['OF']==1) if f['OF'] is not None else None
        if mn in ('jno',): return (f['OF']==0) if f['OF'] is not None else None
        raise RuntimeError('unsupported condition '+mn)

    def step(self):
        if not BASE<=self.pc<END: raise RuntimeError(f'PC outside core {self.pc:#x}')
        ins=list(CS.disasm(RAW[self.pc-BASE:self.pc-BASE+15],self.pc,count=1))
        if not ins: raise RuntimeError(f'undecodable {self.pc:#x}')
        ins=ins[0]; mn=ins.mnemonic; ops=ins.operands
        oldpc=self.pc; self.current_ins=oldpc; self.pc=ins.address+ins.size
        self.steps+=1
        if self.steps>self.instruction_limit: raise RuntimeError('instruction limit')
        if mn=='nop': pass
        elif mn in ('mov','movzx','movsx'):
            v=self.value(ops[1])
            if mn=='movzx' and known(v): v&=(1<<(ops[1].size*8))-1
            if mn=='movsx' and known(v): v=U(signed(v,ops[1].size*8))
            self.write(ops[0],v)
        elif mn=='lea': self.write(ops[0],self.address(ops[1]))
        elif mn=='push': self.push(self.value(ops[0]))
        elif mn=='pop': self.write(ops[0],self.pop())
        elif mn=='pushfd': self.push(FlagWord(tuple(self.flags.items())))
        elif mn=='popfd':
            v=self.pop()
            self.flags=dict(v.status) if isinstance(v,FlagWord) else {k:None for k in self.flags}
        elif mn=='call':
            target=self.value(ops[0]); self.push(self.pc)
            if not known(target): raise RuntimeError(f'unresolved CALL {oldpc:#x} target {target}')
            self.edges.append((oldpc,target,'call')); self.pc=target
        elif mn=='ret':
            target=self.pop()
            if len(ops):
                extra=self.value(ops[0]); self.reg['esp']=self.addr_add(self.reg['esp'],extra)
            if not known(target): raise RuntimeError(f'unresolved RET {oldpc:#x} target {target}')
            self.edges.append((oldpc,target,'ret')); self.pc=target
        elif mn=='jmp':
            target=self.value(ops[0])
            if not known(target): raise RuntimeError(f'unresolved JMP {oldpc:#x} target {target}')
            self.edges.append((oldpc,target,'jmp')); self.pc=target
        elif mn.startswith('j'):
            cond=self.condition(mn)
            if cond is None: raise RuntimeError(f'unknown {mn.upper()} {oldpc:#x} flags {self.flags}')
            target=self.value(ops[0]) if cond else self.pc
            self.edges.append((oldpc,target,mn+(' taken' if cond else ' not-taken')))
            self.pc=target
        elif mn.startswith('cmov'):
            cond=self.condition('j'+mn[4:])
            if cond is None: self.write(ops[0],Unknown('unknown '+mn))
            elif cond: self.write(ops[0],self.value(ops[1]))
        elif mn in ('add','adc','sub','sbb','and','or','xor','cmp','test'):
            a,b=self.value(ops[0]),self.value(ops[1]); bits=ops[0].size*8
            kind={'cmp':'sub','test':'and'}.get(mn,mn)
            same_reg=(ops[0].type==X86_OP_REG and ops[1].type==X86_OP_REG
                      and ops[0].reg==ops[1].reg)
            if same_reg and mn in ('xor','sub','cmp'):
                result,cf,of=0,0,0
            else:
                result,cf,of=self.binary(kind,a,b,bits)
            self.setresult(result,bits,cf,of)
            if mn not in ('cmp','test'): self.write(ops[0],result)
        elif mn in ('inc','dec','neg','not'):
            a=self.value(ops[0]); bits=ops[0].size*8; mask=(1<<bits)-1
            if mn=='not': self.write(ops[0],(~a)&mask if known(a) else Unknown('not symbolic'))
            elif mn=='neg':
                r=(-a)&mask if known(a) else Unknown('neg symbolic')
                self.setresult(r,bits,int(a!=0) if known(a) else None,int(a==(1<<(bits-1))) if known(a) else None)
                self.write(ops[0],r)
            else:
                r,_,of=self.binary('add' if mn=='inc' else 'sub',a,1,bits)
                self.setresult(r,bits,of=of,preserve_cf=True)
                self.write(ops[0],r)
        elif mn in ('shl','sal','shr','sar','rol','ror'):
            a,b=self.value(ops[0]),self.value(ops[1]); bits=ops[0].size*8
            if not known(b): raise RuntimeError('unknown shift count '+str(b))
            count=b&31
            if count:
                if not known(a):
                    r=Unknown('shift symbolic')
                    if mn in ('rol','ror'):
                        # Rotates preserve ZF/SF/PF even for unknown data.
                        self.flags['CF']=self.flags['OF']=None
                    else:
                        self.setresult(r,bits)
                elif mn in ('rol','ror'):
                    rot=count%bits; mask=(1<<bits)-1; a&=mask
                    r=((a<<rot)|(a>>(bits-rot)))&mask if mn=='rol' else ((a>>rot)|(a<<(bits-rot)))&mask
                    self.flags['CF']=(r&1) if mn=='rol' else ((r>>(bits-1))&1)
                    if count==1 and mn=='rol': self.flags['OF']=((r>>(bits-1))&1)^self.flags['CF']
                    elif count==1 and mn=='ror': self.flags['OF']=((r>>(bits-1))&1)^((r>>(bits-2))&1)
                    else: self.flags['OF']=None
                else:
                    mask=(1<<bits)-1; a&=mask
                    if mn in ('shl','sal'):
                        r=(a<<count)&mask; cf=((a>>(bits-count))&1) if count<=bits else None
                        of=(((r>>(bits-1))&1)^cf) if count==1 and cf is not None else None
                    elif mn=='shr':
                        r=a>>count; cf=(a>>(count-1))&1 if count<=bits else None
                        of=((a>>(bits-1))&1) if count==1 else None
                    else:
                        r=signed(a,bits)>>count; r&=mask; cf=(a>>(count-1))&1 if count<=bits else None
                        of=0 if count==1 else None
                    self.setresult(r,bits,cf,of)
                self.write(ops[0],r)
        elif mn in ('bt','bts','btr','btc'):
            if ops[0].type==X86_OP_MEM:
                raise RuntimeError(f'unimplemented memory bit-index semantics at {oldpc:#x}')
            a,b=self.value(ops[0]),self.value(ops[1]); bits=ops[0].size*8
            if known(a) and known(b):
                bit=b%bits; self.flags['CF']=(a>>bit)&1
                if mn=='bts': self.write(ops[0],a|(1<<bit))
                if mn=='btr': self.write(ops[0],a&~(1<<bit))
                if mn=='btc': self.write(ops[0],a^(1<<bit))
            else:
                self.flags['CF']=None
                if mn!='bt': self.write(ops[0],Unknown(mn+' symbolic'))
            # BT-family writes CF; ZF is preserved, while SF/PF/OF are
            # architecturally undefined for this instruction family.
            for k in ('SF','PF','OF'): self.flags[k]=None
        elif mn=='bswap':
            a=self.value(ops[0]); self.write(ops[0],int.from_bytes(a.to_bytes(4,'little'),'big') if known(a) else Unknown('bswap symbolic'))
        elif mn=='cwde':
            ax=self.getreg('ax'); self.setreg('eax',U(signed(ax,16)) if known(ax) else Unknown('cwde symbolic'))
        elif mn=='cbw':
            al=self.getreg('al'); self.setreg('ax',signed(al,8)&0xffff if known(al) else Unknown('cbw symbolic'))
        elif mn=='cdq':
            eax=self.getreg('eax'); self.setreg('edx',MASK if known(eax) and eax&0x80000000 else 0 if known(eax) else Unknown('cdq symbolic'))
        elif mn=='cwd':
            ax=self.getreg('ax'); self.setreg('dx',0xffff if known(ax) and ax&0x8000 else 0 if known(ax) else Unknown('cwd symbolic'))
        elif mn=='imul':
            if len(ops)==1:
                bits=ops[0].size*8
                if bits not in (8,16,32): raise RuntimeError('unsupported IMUL width')
                a=self.getreg('eax' if bits==32 else 'ax' if bits==16 else 'al')
                b=self.value(ops[0])
                if known(a) and known(b):
                    full=signed(a,bits)*signed(b,bits); lo=full&((1<<bits)-1); hi=(full>>bits)&((1<<bits)-1)
                    if bits==8:
                        # 8-bit one-operand IMUL multiplies AL and r/m8 into AX;
                        # unlike the 16/32-bit forms, it never writes DX/EDX.
                        self.setreg('ax',full&0xffff)
                    else:
                        self.setreg('eax' if bits==32 else 'ax',lo)
                        self.setreg('edx' if bits==32 else 'dx',hi)
                    self.flags['CF']=self.flags['OF']=int(full!=signed(lo,bits))
                else:
                    self.setreg('eax' if bits==32 else 'ax',Unknown('imul one'))
                    if bits!=8: self.setreg('edx' if bits==32 else 'dx',Unknown('imul high'))
                    self.flags['CF']=self.flags['OF']=None
            else:
                a,b=self.value(ops[0]),self.value(ops[1]); bits=ops[0].size*8
                if known(a) and known(b):
                    full=signed(a,bits)*signed(b,bits); lo=full&((1<<bits)-1)
                    self.write(ops[0],lo); self.flags['CF']=self.flags['OF']=int(full!=signed(lo,bits))
                else:
                    self.write(ops[0],Unknown('imul two')); self.flags['CF']=self.flags['OF']=None
            for k in ('ZF','SF','PF'): self.flags[k]=None
        elif mn=='mul':
            bits=ops[0].size*8; a=self.getreg('eax' if bits==32 else 'ax' if bits==16 else 'al'); b=self.value(ops[0])
            if known(a) and known(b):
                full=a*b; mask=(1<<bits)-1
                if bits==8: self.setreg('ax',full&0xffff)
                else:
                    self.setreg('eax' if bits==32 else 'ax',full&mask)
                    self.setreg('edx' if bits==32 else 'dx',(full>>bits)&mask)
                self.flags['CF']=self.flags['OF']=int(full>mask)
            else:
                self.setreg('eax' if bits==32 else 'ax',Unknown('mul low'))
                if bits!=8: self.setreg('edx' if bits==32 else 'dx',Unknown('mul high'))
                self.flags['CF']=self.flags['OF']=None
            for k in ('ZF','SF','PF'): self.flags[k]=None
        elif mn in ('div','idiv'):
            bits=ops[0].size*8; divisor=self.value(ops[0])
            if bits not in (8,16,32): raise RuntimeError('unsupported DIV width')
            lo=self.getreg('eax' if bits==32 else 'ax')
            hi=0 if bits==8 else self.getreg('edx' if bits==32 else 'dx')
            if known(divisor) and divisor==0: raise RuntimeError('DIV zero divisor')
            if known(divisor) and known(lo) and known(hi):
                dividend=lo if bits==8 else (hi<<bits)|lo
                if mn=='idiv':
                    dividend=signed(dividend,bits*2); divisor=signed(divisor,bits)
                    q=abs(dividend)//abs(divisor)*(1 if (dividend<0)==(divisor<0) else -1)
                    r=dividend-q*divisor
                    if not -(1<<(bits-1))<=q<(1<<(bits-1)): raise RuntimeError('IDIV quotient overflow')
                else:
                    q,r=divmod(dividend,divisor)
                    if q >= (1<<bits): raise RuntimeError('DIV quotient overflow')
                if bits==8:
                    self.setreg('al',q); self.setreg('ah',r)
                else:
                    self.setreg('eax' if bits==32 else 'ax',q)
                    self.setreg('edx' if bits==32 else 'dx',r)
            else:
                self.events.append(f'{oldpc:08x} {mn.upper()} outcome/fault unresolved')
                if bits==8:
                    self.setreg('al',Unknown(mn+' quotient'))
                    self.setreg('ah',Unknown(mn+' remainder'))
                else:
                    self.setreg('eax' if bits==32 else 'ax',Unknown(mn+' quotient'))
                    self.setreg('edx' if bits==32 else 'dx',Unknown(mn+' remainder'))
            self.flags={k:None for k in self.flags}
        elif mn=='cpuid':
            self.events.append(f'{oldpc:08x} CPUID live result unresolved')
            if not self.continue_cpuid: raise RuntimeError(f'live CPUID boundary {oldpc:#x}')
            for r in ('eax','ebx','ecx','edx'): self.setreg(r,Unknown(f'CPUID output {r} at {oldpc:08x}'))
        elif mn=='xchg':
            # Resolve both effective addresses before either register changes.
            addr0=self.address(ops[0]) if ops[0].type==X86_OP_MEM else None
            addr1=self.address(ops[1]) if ops[1].type==X86_OP_MEM else None
            a,b=self.value(ops[0]),self.value(ops[1])
            if addr0 is not None: self.store(addr0,ops[0].size,b)
            else: self.write(ops[0],b)
            if addr1 is not None: self.store(addr1,ops[1].size,a)
            else: self.write(ops[1],a)
        elif mn=='xadd':
            a,b=self.value(ops[0]),self.value(ops[1]); bits=ops[0].size*8
            result,cf,of=self.binary('add',a,b,bits); self.setresult(result,bits,cf,of)
            self.write(ops[0],result); self.write(ops[1],a)
        elif mn.startswith('set'):
            cond=self.condition('j'+mn[3:])
            self.write(ops[0],int(cond) if cond is not None else Unknown(mn+' unknown'))
        else: raise RuntimeError(f'unsupported {oldpc:#x}: {mn} {ins.op_str}')
        return ins

    def run(self):
        try:
            while True: self.step()
        except RuntimeError as e: self.stop=str(e)
        return self

if __name__=='__main__':
    results={}
    for mode,continue_cpuid in [('strict',False),('symbolic_cpuid',True)]:
        machine=Machine(continue_cpuid=continue_cpuid).run()
        print(mode,'steps',machine.steps,'pc',hex(machine.pc),'stop',machine.stop,
              'edges',len(machine.edges),'descriptor/argument loads',len(machine.loads))
        results[mode]={
            'steps':machine.steps,'pc':f'{machine.pc:08x}','stop':machine.stop,
            'edges':[{'from':f'{a:08x}','to':f'{b:08x}','kind':k} for a,b,k in machine.edges],
            'loads':machine.loads,'events':machine.events,
            'unresolved_reads':machine.unresolved_reads,
            'registers':{k:str(v) for k,v in machine.reg.items()},
            'flags':machine.flags,
            'static_byte_reads':machine.byte_reads,
        }
        if mode=='strict':
            prefix=[
                ('41da0bac','42bd0654'),('42bd066d','42d6a129'),
                ('42d6a129','42c8e7b6'),('42c8e7b6','42b5f7eb'),
                ('42b5f7f3','4315fbd2'),('4315fbf0','4315fbf6'),
                ('4315fcb9','4281e557'),('4281e5ac','42a1bfef'),
                ('42a1c069','42c58fc9'),('42c59016','42907f5d'),
                ('42907f64','425d11ac'),('425d11f5','42a7d5c2'),
                ('42a7d60f','4287dd00'),('4287dd16','425e3566'),
                ('425e35ba','42d5a582'),('42d5a5a4','42d23d7e'),
                ('42d23d98','42e573b7'),('42e573e7','4318e301'),
                ('4318e332','42fd77f7'),('42fd7808','425dcd9a'),
            ]
            actual=[(f'{a:08x}',f'{b:08x}') for a,b,_ in machine.edges[:len(prefix)]]
            assert actual==prefix,(actual,prefix)
            assert machine.stop=='live CPUID boundary 0x4253ad34'
            assert not machine.loads and not machine.unresolved_reads
        else:
            assert machine.stop=='unknown shift count ?(partial cl of ?(partial write cl))'
            assert machine.current_ins==0x4298ca0e
            assert machine.steps==9322 and len(machine.edges)==953
            assert not machine.loads and len(machine.unresolved_reads)==1
    results['sha256']=SHA
    _fc_output('installer_abstract_result.json').write_text(json.dumps(results,indent=2)+'\n',encoding='utf-8')
