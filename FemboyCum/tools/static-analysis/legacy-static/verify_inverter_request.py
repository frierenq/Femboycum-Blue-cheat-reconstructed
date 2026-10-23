from legacy_env import research_root, workspace_root, required_path
"""Verify original inverter request-match and active-result projection blocks."""
from pathlib import Path
import ctypes,hashlib,json,re,struct,sys
research=research_root();root=workspace_root();out=research/'antiaim-accessors'
ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
# Capstone is installed separately; no private dependency directory is used.
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
from capstone.x86_const import X86_OP_MEM,X86_OP_IMM
raw=(research/'ui-controls/nl.core.bin').read_bytes();base=0x412a0000
sha=hashlib.sha256(raw).hexdigest();assert sha=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
cs=Cs(CS_ARCH_X86,CS_MODE_32);cs.detail=True;boundaries=set()
for p in out.glob('*/*.targeted.ghidra.txt'):
    boundaries.update(int(m[1],16) for m in re.finditer(r'^([0-9a-f]{8}) ',p.read_text(),re.M))
def decode(va):return next(cs.disasm(raw[va-base:va-base+16],va))
def record(i):return {'va':hex(i.address),'core_offset':hex(i.address-base),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str}
selected=[];streams=[]
def check(va,mnemonic,operands):
    i=decode(va);assert va in boundaries and (i.mnemonic,i.op_str)==(mnemonic,operands),(hex(va),i.mnemonic,i.op_str)
    selected.append(record(i))
checks={
    0x41360e21:('push','ebx'),0x41360e27:('mov','esi, ecx'),
    0x41360e34:('mov','eax, dword ptr [ecx + 0x40]'),
    0x41360e37:('cmp','eax, dword ptr [0x424f4b18]'),0x41360e3d:('jne','0x41360e78'),
    0x41360e3f:('xor','eax, eax'),0x41360e41:('cmp','byte ptr [esi + 0x44], 0'),
    0x41360e45:('sete','al'),0x41360e48:('movss','xmm0, dword ptr [eax*4 + 0x4206da20]'),
    0x41360e51:('movss','dword ptr [esp + 0x18], xmm0'),0x41360e57:('fld','dword ptr [esp + 0x18]'),
    0x41360e5b:('fstp','xword ptr [esp + 0x28]'),0x41360e65:('call','0x41da7c5c'),
    0x41360e6a:('fld','xword ptr [esp + 0x28]'),0x41360e73:('pop','ebx'),0x41360e75:('ret','8'),
    0x41360e78:('mov','eax, dword ptr [0x424f639c]'),
    0x4136110f:('mov','ecx, dword ptr [esi + 0x40]'),0x41361112:('cmp','ecx, dword ptr [0x424f4b18]'),
    0x41361118:('jne','0x41361133'),0x4136111a:('add','esi, 0x44'),0x4136111d:('jmp','0x41361144'),
    0x41361144:('xor','eax, eax'),0x41361146:('cmp','byte ptr [esi], 0'),0x41361149:('jmp','0x41360e45'),
    0x41368f97:('mov','ebx, dword ptr [esi]'),0x41368f99:('mov','ecx, ebx'),0x41368f9b:('call','0x41360e20'),
    0x41368fa0:('fstp','dword ptr [esi + 0xf8]'),0x41368fa6:('movss','xmm0, dword ptr [esi + 0xf8]'),
    0x41368fae:('xorps','xmm1, xmm1'),0x41368fb1:('ucomiss','xmm0, xmm1'),
    0x41368fb4:('setb','byte ptr [ebx + 0x2b5]'),
    0x41367267:('mov','edi, ecx'),0x41367622:('mov','dword ptr [esi], edi'),
    0x41596aae:('mov','ecx, dword ptr [0x42500648]'),0x41596ab4:('call','0x41367250'),
}
for va,pair in checks.items():check(va,*pair)
for start,end in [(0x41360e20,0x41360e78),(0x41368f97,0x41368fbb)]:
    ins=list(cs.disasm(raw[start-base:end-base],start));assert ins[-1].address+ins[-1].size==end
    assert all(i.address in boundaries for i in ins)
    streams.append({'start':hex(start),'end_exclusive':hex(end),'instructions':[record(i) for i in ins]})
# Matching branch stores only to its stack. No request reset or active write.
for i in cs.disasm(raw[0x41360e20-base:0x41360e78-base],0x41360e20):
    if i.mnemonic.startswith(('mov','fst')) and i.operands[0].type==X86_OP_MEM:
        assert cs.reg_name(i.operands[0].mem.base)=='esp'
assert struct.unpack_from('<2I',raw,0x4206da20-base)==(0xc2700000,0x42700000)
# Static overlap regression: both original branch targets reach the state
# getter call even where a single Ghidra code-unit stream lost its boundary.
graph=json.loads((out/'0x41344740.overlap-cfg-leads.json').read_text())
assert graph['core_sha256']==sha and not graph['whole_cfg_recovered'] and not graph['node_limit_reached']
nodes={int(n['va'],16):n for n in graph['nodes']}
edges={(int(e['from'],16),int(e['to'],16)) for e in graph['edges'] if e['kind']=='branch'}
assert nodes[0x41344a96]['instruction']=='call 0x41b70930'
assert nodes[0x41344a9b]['instruction']=='mov dword ptr [esi + 0x20], eax'
assert (0x41344a5a,0x41344a96) in edges and (0x41344a62,0x41344a96) in edges
for va in [0x41344a96,0x41344a9b]:assert nodes[va]['bytes']==decode(va).bytes.hex()
tests=json.loads((out/'inverter-request-semantic-tests.json').read_text());assert tests['passed'] and tests['semantic_checks']==33
initial=json.loads((research/'ui-controls/initial-map.json').read_text())
installed=root/'outputs/FemboyLose-Build/FemboyLose-local-build/FemboyLose-local-build'
assert {n:hashlib.sha256((installed/n).read_bytes()).hexdigest() for n in initial['installed_files_before']}==initial['installed_files_before']
result={'date':'2026-10-18','passed':True,'core_sha256':sha,
    'scope':'Matching-counter inverter request branch, read-only request reuse and separate active-sign projection block',
    'selected_original_instructions':selected,'original_local_streams':streams,
    'sign_table':{'va':'0x4206da20','nonzero_request':-60.0,'zero_request':60.0},
    'overlap_tool_regression':{'passed':True,'call':'0x41344a96','branch_predecessors':['0x41344a5a','0x41344a62']},
    'tests':tests,'request_match_rule_recovered':True,'whole_inverter_lifecycle_recovered':False,
    'target_runtime_executed':False,'live_process_access':False,'installed_build_unchanged':True,'whole_product_completion_percent':None,
    'limits':['The complete outer method, eligibility gates and preservation of the saved context identity over every obfuscated path are not recovered.',
              'A stale request falls through to other native decisions; nullopt models departure from this branch, not its eventual return or active value.',
              'No claim is made that the Lua setter immediately changes active state, that each request is consumed once, or that it persists over future counter values.',
              'Other decision-helper branches and their external dependencies are not reconstructed in this model.',
              'The x87 return ABI, stack-cookie helper, floating-point exceptions and process concurrency are not reproduced.',
              'The branch index records both conditional successors without feasibility proof; its instruction/edge totals are not feature completion metrics.']}
(out/'inverter-request-verification.json').write_text(json.dumps(result,indent=2))
print(json.dumps({'passed':True,'original_instruction_contracts':len(selected),'local_streams':len(streams),'authored_semantic_checks':tests['semantic_checks'],'whole_inverter_lifecycle_recovered':False,'installed_build_unchanged':True}))
