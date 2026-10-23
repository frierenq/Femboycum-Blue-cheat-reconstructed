"""Bounded static x86 branch index. Never execute/emulate target instructions.

Instruction starts may overlap. Both conditional successors are indexed without
path-feasibility claims; calls are not followed and indirect jumps stay unknown.
"""
from pathlib import Path
import argparse,collections,hashlib,json,re
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--input',type=Path,required=True,help='locally supplied flat x86 image; not distributed with this tool')
parser.add_argument('--base',type=lambda value:int(value,0),required=True,help='image stored virtual-address base')
parser.add_argument('--output-dir',type=Path,required=True)
parser.add_argument('--sha256',help='optional expected SHA-256 of input image')
parser.add_argument('--max-nodes',type=int,default=40000)
parser.add_argument('regions',nargs='+',help='stored_start:stored_end_exclusive')
args=parser.parse_args()
if not 1<=args.max_nodes<=100000:parser.error('--max-nodes must be 1..100000')
if args.sha256 and not re.fullmatch(r'[0-9a-fA-F]{64}',args.sha256):parser.error('--sha256 must be 64 hexadecimal characters')
from capstone import Cs,CS_ARCH_X86,CS_MODE_32,CS_GRP_RET,CS_GRP_JUMP,CS_GRP_CALL,CS_GRP_INT
from capstone.x86_const import X86_OP_IMM,X86_OP_MEM
cs=Cs(CS_ARCH_X86,CS_MODE_32);cs.detail=True;base=args.base
raw=args.input.read_bytes()
sha=hashlib.sha256(raw).hexdigest()
if args.sha256 and sha!=args.sha256.lower():parser.error('input image SHA-256 mismatch')
out=args.output_dir;out.mkdir(parents=True,exist_ok=True)
for region in args.regions:
    if not re.fullmatch(r'0x[0-9a-fA-F]{8}:0x[0-9a-fA-F]{8}',region):parser.error('region must be 0xXXXXXXXX:0xXXXXXXXX')
    start,end=map(lambda n:int(n,16),region.split(':'))
    if not (base<=start<end<=base+len(raw) and end-start<=0x10000):parser.error('region outside image or larger than 64 KiB')
    queue=collections.deque([start]);seen={};edges=[];unresolved=[]
    while queue and len(seen)<args.max_nodes:
        address=queue.popleft()
        if address in seen or not start<=address<end:continue
        i=next(cs.disasm(raw[address-base:min(address-base+15,end-base)],address,count=1),None)
        if i is None:
            unresolved.append({'va':hex(address),'kind':'undecodable bytes'});continue
        seen[address]=i;following=address+i.size;targets=[]
        if i.group(CS_GRP_RET):continue
        if i.group(CS_GRP_INT) or i.mnemonic in ['hlt','ud2','lcall','ljmp','in','out','insb','insw','insd','outsb','outsw','outsd','cli','sti','wbinvd','invd']:
            unresolved.append({'va':hex(address),'kind':'trap/privileged/far control not modeled','instruction':i.mnemonic+' '+i.op_str});continue
        if i.group(CS_GRP_JUMP):
            if i.operands[0].type==X86_OP_IMM:targets.append((i.operands[0].imm&0xffffffff,'branch'))
            else:unresolved.append({'va':hex(address),'kind':'indirect jump','instruction':i.mnemonic+' '+i.op_str})
            if i.mnemonic!='jmp':targets.append((following,'fallthrough'))
        else:targets.append((following,'call fallthrough' if i.group(CS_GRP_CALL) else 'fallthrough'))
        for target,kind in targets:
            edges.append({'from':hex(address),'to':hex(target),'kind':kind,'inside_region':start<=target<end})
            queue.append(target)
    nodes=[{'va':hex(a),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str} for a,i in sorted(seen.items())]
    fields=[]
    for a,i in sorted(seen.items()):
        for operand in i.operands:
            if operand.type==X86_OP_MEM and operand.mem.disp in [0x40,0x44,0x48,0x4c,0x50,0x54,0x58,0x5c,0x60,0x64,0x2b5] and cs.reg_name(operand.mem.base) not in ['esi','ebp']:
                fields.append({'va':hex(a),'instruction':i.mnemonic+' '+i.op_str,'base_register':cs.reg_name(operand.mem.base),'displacement':hex(operand.mem.disp)});break
    obj={'scope':'Input-byte bounded direct-branch index with overlapping instruction starts. Both branch directions are explored without feasibility/dataflow proof; this is a lead index, not a recovered function.',
        'core_sha256':sha,'start':hex(start),'end_exclusive':hex(end),'nodes':nodes,'edges':edges,
        'unresolved_control':unresolved,'node_limit_reached':bool(queue),'field_leads':fields,
        'whole_cfg_recovered':False,'target_runtime_executed':False,'live_process_access':False}
    (out/(hex(start)+'.overlap-cfg-leads.json')).write_text(json.dumps(obj,indent=2))
    print(json.dumps({'region':region,'nodes':len(nodes),'unresolved_controls':len(unresolved),'field_leads':len(fields),'node_limit_reached':bool(queue),'whole_cfg_recovered':False}))
