from legacy_env import research_root, workspace_root, required_path
"""Original context initialization and bounded hidden-angle lifecycle checks."""
from pathlib import Path
import ctypes,hashlib,json,re,struct,sys
research=research_root();root=workspace_root();out=research/'antiaim-accessors'
ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
# Capstone is installed separately; no private dependency directory is used.
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
from capstone.x86_const import X86_OP_MEM,X86_OP_IMM
raw=(research/'ui-controls/nl.core.bin').read_bytes();base=0x412a0000
assert hashlib.sha256(raw).hexdigest()=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
cs=Cs(CS_ARCH_X86,CS_MODE_32);cs.detail=True;functions={};boundaries=set()
for p in out.glob('*/*.targeted.ghidra.txt'):
    for block in re.split(r'(?=^FUNCTION )',p.read_text(),flags=re.M):
        if block.startswith('FUNCTION '):
            addresses=[int(m[1],16) for m in re.finditer(r'^([0-9a-f]{8}) ',block,re.M)]
            functions[int(block[9:17],16)]=addresses;boundaries.update(addresses)
def decoded(va):return next(cs.disasm(raw[va-base:va-base+16],va))
def record(i):return {'va':hex(i.address),'core_offset':hex(i.address-base),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str}
selected=[];streams=[]
def check(va,mnemonic,operands):
    i=decoded(va);assert va in boundaries and (i.mnemonic,i.op_str)==(mnemonic,operands),(hex(va),i.mnemonic,i.op_str)
    selected.append(record(i))
checks={
    0x4133a8e1:('push','0x2d0'),0x4133a8e6:('call','0x41da7b7c'),0x4133a8ee:('mov','esi, eax'),
    0x4133a8f0:('add','eax, 8'),0x4133a8f3:('push','0x2c8'),0x4133a8f8:('push','0'),
    0x4133a8fb:('call','0x4200cf20'),0x4133a96f:('lea','eax, [esi + 0x94]'),
    0x4133a975:('push','0x214'),0x4133a97a:('push','0'),0x4133a97d:('call','0x4200cf20'),
    0x4133a9d5:('mov','dword ptr [0x42500648], esi'),0x4133a9db:('push','0x41343ba0'),
    0x4133a9e0:('call','0x41da7e9b'),0x4200cf37:('imul','eax, eax, 0x1010101'),
    0x4200cf5c:('rep stosb','byte ptr es:[edi], al'),0x4200cf73:('movd','xmm0, eax'),
    0x4200cf77:('pshufd','xmm0, xmm0, 0'),0x4200cf7e:('movups','xmmword ptr [edi], xmm0'),
    0x41343ba0:('mov','eax, dword ptr [0x42500648]'),0x41343ba5:('test','eax, eax'),
    0x41343baa:('call','0x41da7be0'),
    0x414e588b:('mov','eax, dword ptr [0x42500648]'),0x414e5890:('cmp','byte ptr [eax + 0x84], 0'),
    0x414e5897:('je','0x414e58af'),0x414e5899:('movss','xmm0, dword ptr [eax + 0x80]'),
    0x414e58a1:('movss','dword ptr [ebp - 0x34], xmm0'),0x414e58a6:('mov','byte ptr [eax + 0x84], 0'),
    0x414e58ad:('jmp','0x414e58eb'),
    0x414e5df2:('mov','ecx, dword ptr [0x42500648]'),0x414e5df8:('cmp','byte ptr [ecx + 0x8c], 0'),
    0x414e5dff:('je','0x414e5edd'),0x414e5e05:('movss','xmm0, dword ptr [ecx + 0x88]'),
    0x414e5e1b:('call','0x42026d1b'),0x414e5e37:('call','0x42026d1b'),
    0x414e5e45:('xorps','xmm0, xmm0'),0x414e5e6c:('call','0x42031040'),
    0x414e5e90:('cmpltss','xmm2, xmm0'),0x414e5ead:('cmpltss','xmm1, dword ptr [0x4206cddc]'),
    0x414e5ebf:('mov','eax, dword ptr [0x424b03cc]'),0x414e5ec4:('movss','dword ptr [eax + 0xc], xmm1'),
    0x414e5ec9:('mov','ecx, dword ptr [0x42500648]'),0x414e5ecf:('mov','byte ptr [ecx + 0x8c], 0'),
    0x41595990:('cmp','dword ptr [eax + 0x4d30], 0'),0x41595997:('jne','0x415959c8'),
    0x41595999:('mov','eax, dword ptr [0x42500648]'),
}
for va,pair in checks.items():check(va,*pair)
for va,offset in [(0x4159599e,0x8c),(0x415959a5,0x84),(0x415959ac,0x6c),
                  (0x415959b0,0x74),(0x415959b4,0x7c),(0x415959b8,0x90)]:
    check(va,'mov',f'byte ptr [eax + {hex(offset)}], 0')
for start,end in [(0x4133a8e0,0x4133a9ea),(0x414e588b,0x414e58af),(0x414e5df2,0x414e5edd)]:
    ins=list(cs.disasm(raw[start-base:end-base],start));assert ins[-1].address+ins[-1].size==end
    assert all(i.address in boundaries for i in ins)
    streams.append({'start':hex(start),'end_exclusive':hex(end),'instructions':[record(i) for i in ins]})
# Constant projection of a successful allocation: recognized byte-fill calls
# and literal stores only. No target instructions or allocator are executed.
known=[None]*0x2d0;initializers=[]
for va in functions[0x4133a8e0]:
    i=decoded(va);ops=i.operands
    if va in [0x4133a8fb,0x4133a97d]:
        start,size=(8,0x2c8) if va==0x4133a8fb else (0x94,0x214)
        known[start:start+size]=[0]*size
        initializers.append({'at':hex(va),'kind':'zero-byte fill','offset':hex(start),'size':size})
    elif i.mnemonic=='mov' and len(ops)==2 and ops[0].type==X86_OP_MEM and cs.reg_name(ops[0].mem.base)=='esi' and ops[1].type==X86_OP_IMM:
        offset=ops[0].mem.disp;size=ops[0].size;value=ops[1].imm&((1<<(8*size))-1)
        assert 0<=offset and offset+size<=len(known)
        known[offset:offset+size]=list(value.to_bytes(size,'little'));initializers.append(record(i));selected.append(record(i))
    elif i.mnemonic=='movups' and ops[0].type==X86_OP_MEM and cs.reg_name(ops[0].mem.base)=='esi':
        assert i.op_str.endswith(', xmm0') and 0x4133a91e<va<0x4133a97d
        offset=ops[0].mem.disp;known[offset:offset+16]=[0]*16;initializers.append(record(i));selected.append(record(i))
assert all(v is not None for v in known);image=bytes(known)
nonzero=[{'offset':hex(k),'bits':hex(struct.unpack_from('<I',image,k)[0])} for k in range(0,len(image),4) if struct.unpack_from('<I',image,k)[0]]
assert {int(x['offset'],16):int(x['bits'],16) for x in nonzero}=={
    0:0xffffffff,4:0x7f7fffff,0x2c:7,0x40:0xffffffff,0x48:0xffffffff,0x50:0xffffffff,
    0x58:0xffffffff,0x60:0xffffffff,0x2a8:0x7f7fffff,0x2ac:0xffffffff,0x2b0:0xffffffff,0x2bc:0xffffffff}
assert image[0x44]==image[0x84]==image[0x8c]==image[0x2b5]==0
projection={'scope':'Analyst-projected initial data bytes from successful allocation, zero-fill call semantics and original constant stores; no target execution.',
    'allocator_call':'0x4133a8e6','allocation_size':len(image),'context_global':'0x42500648',
    'initial_bytes_hex':image.hex(),'initial_bytes_sha256':hashlib.sha256(image).hexdigest(),
    'nonzero_aligned_words':nonzero,'initializers':initializers,'cleanup_callback':'0x41343ba0'}
(out/'context-initialization.json').write_text(json.dumps(projection,indent=2))
tests=json.loads((out/'hidden-override-semantic-tests.json').read_text());assert tests['passed'] and tests['semantic_checks']==20
initial=json.loads((research/'ui-controls/initial-map.json').read_text())
installed=root/'outputs/FemboyLose-Build/FemboyLose-local-build/FemboyLose-local-build'
after={n:hashlib.sha256((installed/n).read_bytes()).hexdigest() for n in initial['installed_files_before']}
assert after==initial['installed_files_before']
unique={i['va']:i for i in selected}
result={'date':'2026-10-18','passed':True,'core_sha256':initial['core_sha256'],
    'scope':'Context initialization projection; local hidden-yaw copy/clear, hidden-pitch normalization/write/clear and conditional six-flag reset',
    'selected_original_instructions':list(unique.values()),'original_local_streams':streams,'initialization_projection':projection,
    'tests':tests,'inverter_request_consumption_recovered':False,'whole_hidden_override_lifecycle_recovered':False,
    'target_runtime_executed':False,'live_process_access':False,'installed_build_unchanged':True,'whole_product_completion_percent':None,
    'limits':['Outer consumer/update/event paths and all eligibility gates remain incomplete; the model assumes the checked blocks are reached.',
              'Yaw is copied and consumed before later processing; that later yaw processing is not modeled here.',
              'The local pitch write wraps to [-180,180] and clears its flag; later processing elsewhere is not excluded.',
              'Native allocation failure, cleanup/lifetime ordering, CRT/FPU exception state and full Lua ABI are not reproduced.',
              'Context methods 0x413611c0/0x41367250 and nested 0x41362a50 remain partial exports; no whole-method reconstruction credit is assigned.']}
(out/'hidden-override-verification.json').write_text(json.dumps(result,indent=2))
print(json.dumps({'passed':True,'original_instruction_contracts':len(unique),'context_allocation_size':len(image),'authored_semantic_checks':20,'whole_lifecycle_recovered':False,'installed_build_unchanged':True}))
