from legacy_env import research_root, workspace_root, required_path
"""Check paired native callbacks, strict Boolean dispatch and pending writes."""
from pathlib import Path
import ctypes,hashlib,json,re,struct,sys
research=research_root();root=workspace_root();out=research/'antiaim-accessors'
ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
# Capstone is installed separately; no private dependency directory is used.
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
raw=(research/'ui-controls/nl.core.bin').read_bytes();base=0x412a0000
assert hashlib.sha256(raw).hexdigest()=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
cs=Cs(CS_ARCH_X86,CS_MODE_32);functions={};boundaries=set()
for p in out.glob('*/*.targeted.ghidra.txt'):
    for block in re.split(r'(?=^FUNCTION )',p.read_text(),flags=re.M):
        if block.startswith('FUNCTION '):
            addresses=[int(m[1],16) for m in re.finditer(r'^([0-9a-f]{8}) ',block,re.M)]
            functions[int(block[9:17],16)]=addresses;boundaries.update(addresses)
def decoded(va):return next(cs.disasm(raw[va-base:va-base+16],va))
def record(i):return {'va':hex(i.address),'core_offset':hex(i.address-base),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str}
selected=[];edges=[]
def check(va,mnemonic,operands):
    i=decoded(va);assert va in boundaries and (i.mnemonic,i.op_str)==(mnemonic,operands),(hex(va),i.mnemonic,i.op_str)
    selected.append(record(i))
def edge(source,target,wanted=None):
    matches=[]
    for va in functions[source]:
        i=decoded(va)
        if (i.mnemonic in ('call','jmp') and i.op_str==hex(target)) or (i.mnemonic in ('mov','push') and i.op_str.split(', ')[-1]==hex(target)):
            matches.append(record(i))
    assert matches and (wanted is None or len(matches)==wanted),(hex(source),hex(target),len(matches))
    edges.append({'source':hex(source),'target':hex(target),'instructions':matches})
definitions=[
    ('inverter',0x24c,0x41a2d810,0x419f4f40,0x41983540,0x41973bd0,0x419285e0,0x419838d2,0x420e32e0),
    ('get_rotation',0x254,0x41958980,0x4199b590,0x41a1db90,0x419d9d30,0x41943e40,0x41a1df22,0x420e354c),
    ('get_target',0x25c,0x419c8400,0x419d41d0,0x41a23930,0x4196ecb0,0x4195ca20,0x41a23cc2,0x420e20ec),
]
bindings=json.loads((out/'named-bindings.json').read_text())[0]['bindings'];mapped=[]
for name,slot,first,second,descriptor,generic,dispatch,init,vtable in definitions:
    b=next(b for b in bindings if b['name']==name);assert b['slot']==hex(slot) and b['native_target']==hex(first)
    stores=[]
    for offset,target in [(slot,first),(slot+4,second)]:
        matches=[decoded(va) for va in functions[0x4191b400] if va<int(b['call'],16) and decoded(va).mnemonic=='mov' and decoded(va).op_str==f'dword ptr [esi + {hex(offset)}], {hex(target)}']
        assert len(matches)==1;selected.append(record(matches[0]));stores.append(record(matches[0]))
    check(init,'mov',f'dword ptr [ecx], {hex(vtable)}')
    check(init+6,'movsd','xmm0, qword ptr [eax]');check(init+12,'movsd','qword ptr [ecx + 4], xmm0')
    assert struct.unpack_from('<I',raw,vtable-base)[0]==0x412a6440
    edge(int(b['helper'],16),descriptor);edge(descriptor,generic);edge(generic,dispatch)
    edge(generic,0x41db9040);edge(dispatch,0x419dd960);edge(dispatch,0x41db9350)
    mapped.append({'name':name,'native_callbacks':[hex(first),hex(second)],'registrar_payload_slot':hex(slot),
        'native_pointer_stores':stores,'descriptor_registrar':hex(descriptor),'descriptor_vtable':hex(vtable),
        'generic_callback':hex(generic),'dispatcher':hex(dispatch),
        'dispatch_scope':'Validated leading object + no extra argument, or + one exact Lua Boolean; not the complete Lua ABI.'})
checks={
    0x41928602:('cmp','eax, 1'),0x4192860b:('cmp','eax, 2'),0x4192867d:('cmp','eax, 1'),
    0x41943e62:('cmp','eax, 1'),0x41943e6b:('cmp','eax, 2'),0x41943edd:('cmp','eax, 1'),
    0x4195ca42:('cmp','eax, 1'),0x4195ca4b:('cmp','eax, 2'),0x4195cabd:('cmp','eax, 1'),
    0x419f4f40:('movzx','eax, byte ptr [esp + 4]'),0x419f4f45:('cmp','byte ptr [0x425007f0], 0'),
    0x419f4f4c:('je','0x419f4f56'),0x419f4f4e:('mov','ecx, dword ptr [0x424f4b18]'),
    0x419f4f56:('mov','ecx, dword ptr [0x4223f428]'),0x419f4f5c:('mov','edx, dword ptr [ecx + 0x4d2c]'),
    0x419f4f62:('mov','ecx, dword ptr [ecx + 0x4d30]'),0x419f4f68:('add','ecx, edx'),0x419f4f6a:('inc','ecx'),
    0x419f4f6b:('mov','edx, dword ptr [0x42500648]'),0x419f4f71:('mov','dword ptr [edx + 0x40], ecx'),
    0x419f4f74:('mov','byte ptr [edx + 0x44], al'),0x41a2d815:('movzx','eax, byte ptr [eax + 0x2b5]'),
    0x4199b594:('movzx','eax, byte ptr [esp + 0x34]'),0x4199b5a5:('test','al, al'),
    0x4199b5a7:('je','0x4199b5b3'),0x4199b5a9:('movss','xmm0, dword ptr [0x424f4a90]'),
    0x4199b5b3:('movss','xmm0, dword ptr [0x424f46b8]'),
    # Original branch entries prove the following state-pointer assignment stream.
    0x41344a5a:('je','0x41344a96'),0x41344a62:('ja','0x41344a96'),
    0x41345903:('mov','eax, dword ptr [esi + 0x20]'),0x41345906:('movss','xmm0, dword ptr [eax + 0x80]'),
}
for va,pair in checks.items():check(va,*pair)
edge(0x4199b590,0x42026d1b,2);edge(0x4199b590,0x42031040,1)
branch_stream=list(cs.disasm(raw[0x41344a96-base:0x41344abc-base],0x41344a96))
assert branch_stream[-1].address+branch_stream[-1].size==0x41344abc
assert [(i.mnemonic,i.op_str) for i in branch_stream[:2]]==[('call','0x41b70930'),('mov','dword ptr [esi + 0x20], eax')]
tests=json.loads((out/'overload-semantic-tests.json').read_text());assert tests['passed'] and tests['semantic_checks']==30
initial=json.loads((research/'ui-controls/initial-map.json').read_text())
installed=root/'outputs/FemboyLose-Build/FemboyLose-local-build/FemboyLose-local-build'
after={n:hashlib.sha256((installed/n).read_bytes()).hexdigest() for n in initial['installed_files_before']}
assert after==initial['installed_files_before']
unique={i['va']:i for i in selected}
result={'date':'2026-10-18','passed':True,'core_sha256':initial['core_sha256'],
    'scope':'Three paired API descriptors/generic overload dispatchers; inverter pending-write leaf and Boolean rotation cache selector; whole lifecycle/target selection excluded',
    'overload_bindings':mapped,'selected_original_instructions':list(unique.values()),'captured_pointer_and_call_edges':edges,
    'original_state_pointer_assignment_stream':[record(i) for i in branch_stream],
    'state_pointer_stream_basis':'Original JE/JA targets at 0x41344a5a/0x41344a62. Ghidra overlapping stream is not used or patched.',
    'tests':tests,'pending_inverter_request_consumption_recovered':False,'whole_boolean_target_algorithm_recovered':False,
    'target_runtime_executed':False,'live_process_access':False,'installed_build_unchanged':True,'whole_product_completion_percent':None,
    'limits':['A validated leading object is a model precondition; complete conversion/lifetime, factory closures and stack/error side effects remain open.',
              'The inverter setter records fields +0x40/+0x44; the separate active getter reads +0x2b5. Consumption/reset semantics remain unknown.',
              'The Boolean rotation function selects a second cache and normalizes once; default native function normalizes twice.',
              'The original state-getter assignment and later +0x80 read are checked local facts; whole intervening CFG/alias analysis is incomplete.',
              'No hidden-yaw setter-to-rotation handoff, complete target selection, resolver or gameplay fidelity is claimed.']}
(out/'api-overload-bindings.json').write_text(json.dumps(mapped,indent=2))
(out/'overload-verification.json').write_text(json.dumps(result,indent=2))
print(json.dumps({'passed':True,'paired_api_descriptors':3,'original_instruction_contracts':len(unique),'callable_edges':len(edges),'authored_semantic_checks':30,'installed_build_unchanged':True}))
