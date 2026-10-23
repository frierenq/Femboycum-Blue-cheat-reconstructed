from legacy_env import research_root, workspace_root, required_path
"""Original-file checks for property traversal and animation predicate slices."""
from pathlib import Path
import ctypes,hashlib,json,re,struct,sys
research=research_root();root=workspace_root();out=research/'native-consumers'
ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
# Capstone is installed separately; no private dependency directory is used.
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
data=(research/'ui-controls/nl.core.bin').read_bytes();base=0x412a0000
assert hashlib.sha256(data).hexdigest()=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
cs=Cs(CS_ARCH_X86,CS_MODE_32);cs.detail=True;boundaries=set()
for p in out.glob('*/*.targeted.ghidra.txt'):
    boundaries.update(int(m[1],16) for m in re.finditer(r'^([0-9a-f]{8}) ',p.read_text(),re.M))
def record(i):return {'va':hex(i.address),'core_offset':hex(i.address-base),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str}
streams=[]
for start,end in [(0x41b89240,0x41b892d8),(0x41b89800,0x41b89848),
                  (0x413be1b3,0x413be1dd),(0x41b74a0c,0x41b74a33)]:
    instructions=list(cs.disasm(data[start-base:end-base],start))
    assert instructions[-1].address+instructions[-1].size==end
    # The jump at 0x41b89817 skips alignment padding to 0x41b89827.
    # Ghidra omits the unreachable seven-byte NOP at 0x41b89819.
    assert all(i.address in boundaries or (i.address==0x41b89819 and i.mnemonic=='nop') for i in instructions)
    local={i.address for i in instructions}
    for i in instructions:
        if i.mnemonic.startswith('j') and i.op_str.startswith('0x'):
            target=int(i.op_str,16)
            if start<=target<end:assert target in local
    streams.append({'start':hex(start),'end_exclusive':hex(end),
        'unreachable_alignment_padding':[hex(i.address) for i in instructions if i.address not in boundaries],
        'original_bytes_sha256':hashlib.sha256(data[start-base:end-base]).hexdigest(),
        'instructions':[record(i) for i in instructions]})
selected=[]
def check(va,mnemonic,operands):
    i=next(cs.disasm(data[va-base:va-base+16],va))
    assert va in boundaries and (i.mnemonic,i.op_str)==(mnemonic,operands),(hex(va),i.mnemonic,i.op_str)
    selected.append(record(i))
checks={
    # Direct hash/descriptor pairs precede child traversal.
    0x41b89250:('mov','eax, dword ptr [edx + 0x10]'),0x41b89253:('mov','ecx, dword ptr [edx + 0x14]'),
    0x41b89260:('cmp','dword ptr [eax], ebp'),0x41b89262:('je','0x41b8929f'),
    0x41b89264:('add','eax, 8'),0x41b8926b:('mov','edi, dword ptr [edx + 0x1c]'),
    0x41b8926e:('mov','ebx, dword ptr [edx + 0x20]'),0x41b89280:('cmp','dword ptr [edi + 8], ebp'),
    0x41b89283:('je','0x41b892b3'),0x41b89288:('call','0x41b89240'),
    0x41b89290:('test','eax, eax'),0x41b89292:('jne','0x41b892c8'),
    0x41b89294:('add','edi, 0x2c'),0x41b8929b:('xor','ecx, ecx'),
    0x41b8929f:('test','esi, esi'),0x41b892a3:('mov','ecx, dword ptr [eax + 4]'),
    0x41b892a6:('mov','dword ptr [esi], ecx'),0x41b892a8:('mov','eax, dword ptr [eax + 4]'),
    0x41b892ab:('mov','ecx, dword ptr [eax + 0x2c]'),0x41b892ae:('add','ecx, dword ptr [edx + 0xc]'),
    0x41b892b3:('test','esi, esi'),0x41b892b7:('mov','eax, dword ptr [edi + 4]'),
    0x41b892ba:('mov','dword ptr [esi], eax'),0x41b892bc:('mov','ecx, dword ptr [edi + 0xc]'),
    0x41b892c3:('add','ecx, dword ptr [eax + 0xc]'),0x41b892cc:('add','eax, dword ptr [ecx + 0xc]'),
    # Top-level exact table key, 44-byte stride and zero-result continuation.
    0x41b89804:('mov','edi, dword ptr [ecx]'),0x41b89806:('mov','ebx, dword ptr [ecx + 4]'),
    0x41b89820:('add','edi, 0x2c'),0x41b89827:('cmp','dword ptr [edi], ebp'),
    0x41b89829:('jne','0x41b89820'),0x41b89831:('call','0x41b89240'),
    0x41b89839:('test','eax, eax'),0x41b8983b:('je','0x41b89820'),
    0x41b8983f:('xor','eax, eax'),
    # Native consumer: context-dependent layer-9 path versus cached property fallback.
    0x413bdded:('movzx','eax, byte ptr [ecx + 0xe434]'),0x413bddf4:('shl','eax, 4'),
    0x413bddf7:('cmp','dword ptr [eax + ecx + 0xe420], 0'),0x413bddff:('je','0x413be1dd'),
    0x413bde07:('push','9'),0x413bde09:('call','0x41b73970'),
    0x413bde0e:('cmp','dword ptr [eax + 0x30], 0'),0x413bde12:('je','0x413be1cc'),
    0x413be1b3:('movss','xmm0, dword ptr [0x4205a554]'),
    0x413be1bb:('ucomiss','xmm0, dword ptr [edi + 0x2c]'),0x413be1bf:('jbe','0x413be1cc'),
    0x413be1c1:('mov','al, 1'),0x413be1c3:('xorps','xmm0, xmm0'),
    0x413be1c6:('ucomiss','xmm0, dword ptr [edi + 0x20]'),0x413be1ca:('jne','0x413be1ce'),
    0x413be1cc:('xor','eax, eax'),0x413be1df:('call','0x41b749c0'),
    0x41b74a0c:('mov','eax, dword ptr [0x42515d7c]'),0x41b74a11:('movss','xmm0, dword ptr [0x420a275c]'),
    0x41b74a19:('ucomiss','xmm0, dword ptr [esi + eax - 8]'),0x41b74a1e:('setb','al'),
    0x41b74a53:('call','0x412ab8a0'),0x41b74a5a:('push','0'),
    0x41b74a5c:('push','0xf0bbed9d'),0x41b74a61:('push','0x72822e7f'),
    0x41b74a66:('call','0x41b89800'),0x41b74a6b:('mov','dword ptr [0x42515d7c], eax'),
}
for va,pair in checks.items():check(va,*pair)
assert struct.unpack_from('<I',data,0x4205a554-base)[0]==0x3f800000
assert struct.unpack_from('<I',data,0x420a275c-base)[0]==0x43480000
tests=json.loads((out/'property-semantic-tests.json').read_text());assert tests['passed'] and tests['semantic_checks']==33
initial=json.loads((research/'ui-controls/initial-map.json').read_text())
installed=root/'outputs/FemboyLose-Build/FemboyLose-local-build/FemboyLose-local-build'
after={n:hashlib.sha256((installed/n).read_bytes()).hexdigest() for n in initial['installed_files_before']}
assert after==initial['installed_files_before']
result={'date':'2026-10-18','passed':True,'core_sha256':initial['core_sha256'],
    'scope':'Original local algorithms 0x41b89240/0x41b89800 and comparison slices; excludes registry construction, hash generation and full consumer CFG',
    'selected_original_instructions':selected,'original_instruction_streams':streams,'tests':tests,
    'fallback_lookup_keys':{'table':'0x72822e7f','property':'0xf0bbed9d','cached_offset':'0x42515d7c','read_bias':-8,'threshold':200.0},
    'layer_index':9,'cycle_threshold':1.0,'fallback_property_name_verified':False,
    'hash_generation_algorithm_recovered':False,'registry_construction_recovered':False,
    'whole_animation_consumer_recovered':False,'target_runtime_executed':False,'live_process_access':False,
    'installed_build_unchanged':True,'whole_product_completion_percent':None,
    'limits':['The models use authored tree/descriptor fixtures and already-read float values, not actual native memory or game data.',
              'Native pointer validity, cyclic/corrupt tables, registry population, metadata lifetime and exception paths are not modeled.',
              'The layer path contains a call to absent external activity code before its comparison tail; no side-effect equivalence is asserted.',
              'Float rules assume ordinary masked exceptions; original floating-point exception state is not reproduced.',
              'The hashed fallback property remains unnamed; no gameplay/flash/resolver behavior is inferred from context alone.']}
(out/'property-verification.json').write_text(json.dumps(result,indent=2))
(out/'property-selected-contracts.asm.txt').write_text('\n'.join(i['va']+' '+i['bytes']+' '+i['instruction'] for i in selected)+'\n')
print(json.dumps({'passed':True,'original_instruction_contracts':len(selected),'complete_local_lookup_streams':2,'authored_semantic_checks':tests['semantic_checks'],'installed_build_unchanged':True}))
