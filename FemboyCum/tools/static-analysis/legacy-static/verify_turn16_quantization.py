from legacy_env import research_root, workspace_root, required_path
"""Check original turn16 numeric helper and bounded alternate-cache writer slices."""
from pathlib import Path
import ctypes,hashlib,json,re,struct,sys
research=research_root();root=workspace_root();out=research/'antiaim-accessors'
ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
# Capstone is installed separately; no private dependency directory is used.
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
raw=(research/'ui-controls/nl.core.bin').read_bytes();base=0x412a0000
sha=hashlib.sha256(raw).hexdigest();assert sha=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
cs=Cs(CS_ARCH_X86,CS_MODE_32);cs.detail=True;boundaries=set()
for p in out.glob('*/*.targeted.ghidra.txt'):
    boundaries.update(int(m[1],16) for m in re.finditer(r'^([0-9a-f]{8}) ',p.read_text(),re.M))
graph=json.loads((out/'0x41347370.overlap-cfg-leads.json').read_text())
assert graph['core_sha256']==sha and not graph['node_limit_reached'] and not graph['whole_cfg_recovered']
overlap={int(n['va'],16):n for n in graph['nodes']}
def decode(va):return next(cs.disasm(raw[va-base:va-base+16],va))
def record(i):return {'va':hex(i.address),'core_offset':hex(i.address-base),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str}
selected=[];streams=[]
def checked(va,mnemonic,operands):
    i=decode(va);assert (i.mnemonic,i.op_str)==(mnemonic,operands),(hex(va),i.mnemonic,i.op_str)
    if va not in boundaries:
        assert va in overlap and overlap[va]['bytes']==i.bytes.hex() and overlap[va]['instruction']==i.mnemonic+' '+i.op_str
    selected.append(record(i))
checks={
    0x415738f0:('push','eax'),0x415738f1:('movss','xmm0, dword ptr [esp + 8]'),
    0x415738f7:('mulss','xmm0, dword ptr [0x4209fd20]'),0x415738ff:('cvttss2si','eax, xmm0'),
    0x41573903:('movzx','eax, ax'),0x41573906:('xorps','xmm0, xmm0'),
    0x41573909:('cvtsi2ss','xmm0, eax'),0x4157390d:('mulss','xmm0, dword ptr [0x4209fd24]'),
    0x41573915:('movss','dword ptr [esp], xmm0'),0x4157391a:('fld','dword ptr [esp]'),
    0x4157391d:('pop','eax'),0x4157391e:('ret',''),
    0x4134737c:('movss','xmm0, dword ptr [ebp + 8]'),0x413473ad:('call','0x415738f0'),
    0x413473b5:('fstp','dword ptr [ebp - 0x78]'),0x413473bb:('movss','xmm0, dword ptr [ebp + 0xc]'),
    0x413473c5:('call','0x415738f0'),0x413473cd:('fstp','dword ptr [ebp - 0x74]'),
    0x413473d3:('movss','xmm0, dword ptr [ebp + 0x10]'),0x413473dd:('call','0x415738f0'),
    0x413473e5:('fstp','dword ptr [ebp - 0x70]'),
    0x41347753:('movss','xmm0, dword ptr [ebp - 0x74]'),
    0x41347758:('movss','dword ptr [0x424b00e0], xmm0'),
    0x41348013:('movss','xmm0, dword ptr [0x424b00e0]'),
    0x4134801b:('mov','dword ptr [0x424f4a8c], 0'),
    0x41348025:('movss','dword ptr [0x424f4a90], xmm0'),
    0x4134802d:('mov','dword ptr [0x424f4a94], 0'),
    0x4199b5a5:('test','al, al'),0x4199b5a7:('je','0x4199b5b3'),
    0x4199b5a9:('movss','xmm0, dword ptr [0x424f4a90]'),
    0x4199b5b3:('movss','xmm0, dword ptr [0x424f46b8]'),
}
for va,pair in checks.items():checked(va,*pair)
for start,end,scope in [(0x415738f0,0x4157391f,'Complete local numeric leaf'),
    (0x41347370,0x413473e8,'Caller entry and three argument conversions'),
    (0x41347753,0x41347760,'Overlap-indexed local staging store, outer path incomplete'),
    (0x41348013,0x41348037,'Local alternate-cache refresh, outer path incomplete')]:
    ins=list(cs.disasm(raw[start-base:end-base],start));assert ins[-1].address+ins[-1].size==end
    for i in ins:
        assert i.address in boundaries or (i.address in overlap and overlap[i.address]['bytes']==i.bytes.hex())
    streams.append({'start':hex(start),'end_exclusive':hex(end),'scope':scope,'instructions':[record(i) for i in ins]})
assert struct.unpack_from('<I',raw,0x4209fd20-base)[0]==0x43360b61
assert struct.unpack_from('<I',raw,0x4209fd24-base)[0]==0x3bb40000
constants={'scale':{'va':'0x4209fd20','bits':'0x43360b61','value':struct.unpack_from('<f',raw,0x4209fd20-base)[0]},
    'unit':{'va':'0x4209fd24','bits':'0x3bb40000','value':struct.unpack_from('<f',raw,0x4209fd24-base)[0]}}
tests=json.loads((out/'turn16-semantic-tests.json').read_text())
assert tests['passed'] and tests['semantic_checks']==58 and tests['quantized_codes_checked']==65536
initial=json.loads((research/'ui-controls/initial-map.json').read_text())
installed=root/'outputs/FemboyLose-Build/FemboyLose-local-build/FemboyLose-local-build'
assert {n:hashlib.sha256((installed/n).read_bytes()).hexdigest() for n in initial['installed_files_before']}==initial['installed_files_before']
result={'date':'2026-10-18','passed':True,'core_sha256':sha,
    'scope':'Complete local turn16 quantization leaf and selected producer/staging/alternate-read blocks',
    'selected_original_instructions':selected,'original_streams':streams,'constants':constants,'tests':tests,
    'architecture_reference':{'title':'Intel 64 and IA-32 Architectures Software Developer Manual, Volume 2, CVTTSS2SI',
        'url':'https://cdrdv2-public.intel.com/782156/325383-sdm-vol-2abcd.pdf',
        'masked_invalid_reference':'https://cdrdv2-public.intel.com/868137/325462-089-sdm-vol-1-2abcd-3abcd-4.pdf',
        'scope':'Instruction semantics only; all application-specific joins come from original local bytes.'},
    'whole_rotation_writer_recovered':False,'target_runtime_executed':False,'live_process_access':False,
    'installed_build_unchanged':True,'whole_product_completion_percent':None,
    'limits':['The enclosing writer has unresolved/overlapping control flow, eligibility conditions and state reuse; no unconditional per-call cache refresh is claimed.',
              'The staging assignment and alternate-cache copy are separately verified local blocks; preservation of the frame/temp and all path combinations remain incomplete.',
              'The model uses SSE under ordinary round-to-nearest and masked exceptions; original FP exception delivery/status and x87 return ABI are not reproduced.',
              'The accessor-composition tests are authored numeric fixtures and do not execute or establish reachability of the original writer.',
              'The original gameplay names/meaning of the three input angles, full context aliases and complete resolver remain open.']}
(out/'turn16-verification.json').write_text(json.dumps(result,indent=2))
print(json.dumps({'passed':True,'original_instruction_contracts':len(selected),'original_local_streams':len(streams),
    'authored_semantic_checks':58,'roundtrip_codes_checked':65536,'whole_rotation_writer_recovered':False,'installed_build_unchanged':True}))
