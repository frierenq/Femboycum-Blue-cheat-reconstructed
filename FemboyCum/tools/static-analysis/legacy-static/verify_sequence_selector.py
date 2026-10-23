from legacy_env import research_root, workspace_root, required_path
from pathlib import Path
import ctypes,hashlib,json,re,struct,sys
root=workspace_root();research=research_root();out=research/'native-consumers'
ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
# Capstone is installed separately; no private dependency directory is used.
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
raw=(research/'ui-controls/nl.core.bin').read_bytes();base=0x412a0000
assert hashlib.sha256(raw).hexdigest()=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
cs=Cs(CS_ARCH_X86,CS_MODE_32);boundaries=set()
# Conditional derivatives are deliberately excluded from instruction evidence.
for path in out.glob('*/*.targeted.ghidra.txt'):
 boundaries.update(int(m[1],16) for m in re.finditer(r'^([0-9a-f]{8}) ',path.read_text(),re.M))
def decoded(va):return next(cs.disasm(raw[va-base:va-base+16],va))
def record(i):return {'va':hex(i.address),'core_offset':hex(i.address-base),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str}
# The original Ghidra function has overlaps at shared blocks. Decode the
# selector streams from the actual original jump-table entries and branch
# targets. No derivative bytes or zero/range assumptions participate here.
dispatch_entries=list(struct.unpack_from('<5I',raw,0x4134b8a4-base))
assert dispatch_entries==[0x4134af85,0x4134b005,0x4134afc5,0x4134afe5,0x4134afa5]
streams=[]
for start,end in [(0x4134af6d,0x4134af85),*( (e,e+0x20) for e in dispatch_entries if e!=0x4134b005 ),(0x4134b005,0x4134b023),(0x4134b023,0x4134b03d),(0x4134b4cb,0x4134b4e4)]:
 ins=list(cs.disasm(raw[start-base:end-base],start));assert ins[-1].address+ins[-1].size==end
 boundaries.update(i.address for i in ins);streams.append({'start':hex(start),'end_exclusive':hex(end),'instructions':[record(i) for i in ins]})
for entry in dispatch_entries:
 if entry!=0x4134b005:
  jump=decoded(entry+0x1e);assert jump.mnemonic=='jmp' and jump.op_str=='0x4134b023'
tail_branch=decoded(0x4134b496);assert tail_branch.mnemonic=='je' and tail_branch.op_str=='0x4134b4cb'
selected=[]
def check(va,mnemonic,operands):
 i=decoded(va);assert va in boundaries and (i.mnemonic,i.op_str)==(mnemonic,operands),(hex(va),i.mnemonic,i.op_str)
 selected.append(record(i))
checks={
0x4134abc8:('call','0x41b70930'),0x4134abcd:('movss','xmm0, dword ptr [eax + 0xa4]'),
0x4134abd5:('movss','xmm1, dword ptr [eax + 0xfc]'),0x4134af6d:('mov','eax, dword ptr [ebp + 0xc]'),
0x4134af70:('add','eax, 0xfffffc27'),0x4134af75:('cmp','eax, 4'),0x4134af78:('ja','0x4134b4e4'),
0x4134af7e:('jmp','dword ptr [eax*4 + 0x4134b8a4]'),0x4134b023:('cmovbe','edi, edx'),
0x4134b026:('ucomiss','xmm0, dword ptr [0x4206ce34]'),0x4134b02d:('cmovbe','eax, ecx'),
0x4134b030:('cmovbe','eax, edi'),0x4134b033:('mov','ebx, dword ptr [eax]'),
0x4134b035:('test','ebx, ebx'),0x4134b037:('jle','0x4134b4e4'),
0x4134b4cd:('call','dword ptr [esi + 0x2c]'),0x4134b4d0:('fstp','dword ptr [edi + 0x28]'),
0x4134b4d3:('mov','dword ptr [edi + 0x18], ebx'),0x4134b4d6:('mov','dword ptr [edi + 0x20], 0'),
0x4134b4dd:('mov','dword ptr [edi + 0x2c], 0'),
}
for va,expected in checks.items():check(va,*expected)
entries=list(struct.unpack_from('<5I',raw,0x4134b8a4-base));assert entries==[0x4134af85,0x4134b005,0x4134afc5,0x4134afe5,0x4134afa5]
bases=[0x4223f430,0x4223f418,0x4223f2f8,0x4223f370,0x4223f380]
cases=[]
for selector,(entry,cache_base) in enumerate(zip(entries,bases),985):
 expected=[('ucomiss','xmm1, dword ptr [0x4206cdf4]'),('mov',f'eax, {hex(cache_base+12)}'),
 ('mov',f'ecx, {hex(cache_base+8)}'),('cmovbe','eax, ecx'),('mov',f'edx, {hex(cache_base)}'),('mov',f'edi, {hex(cache_base+4)}')]
 address=entry
 for mnemonic,operands in expected:
  check(address,mnemonic,operands);address+=decoded(address).size
 cases.append({'selector':selector,'case_entry':hex(entry),'cache_slots':[hex(cache_base+k*4) for k in range(4)],'stored_input_cache_values':list(struct.unpack_from('<4i',raw,cache_base-base))})
assert struct.unpack_from('<I',raw,0x4206cdf4-base)[0]==0x3e800000
assert struct.unpack_from('<I',raw,0x4206ce34-base)[0]==0x3f0ccccd
tests=json.loads((out/'semantic-tests.json').read_text());assert tests['passed'] and tests['semantic_checks']==34
# Audit derivative records as separate hypotheses, not native-function results.
derivatives=[]
for folder in ['animation-zero-guard-v1','animation-zero-guard-v2','animation-range-guard-v3']:
 obj=json.loads((out/folder/'guard-assumptions.json').read_text())
 for p in obj['patches']:
  va=int(p['branch'],16);before=bytes.fromhex(p['original']);after=bytes.fromhex(p['analysis_replacement'])
  assert raw[va-base:va-base+len(before)]==before and len(before)==len(after)
 derivatives.append({'folder':folder,'overrides':len(obj['patches']),'native_reconstruction_credit':False,'runtime_invariant_verified':False})
initial=json.loads((research/'ui-controls/initial-map.json').read_text());installed=root/'outputs/FemboyLose-Build/FemboyLose-local-build/FemboyLose-local-build'
after={n:hashlib.sha256((installed/n).read_bytes()).hexdigest() for n in initial['installed_files_before']};assert after==initial['installed_files_before']
result={'date':'2026-10-18','passed':True,'scope':'Original native selector slice 0x4134af6d..0x4134b03d plus separate observed layer-write tail; not full consumer control flow','core_sha256':initial['core_sha256'],'selected_instructions':selected,'original_dispatch_and_branch_streams':streams,'selector_cases':cases,'speed_threshold':0.25,'duck_threshold_float_bits':'0x3f0ccccd','tests':tests,'conditional_derivatives_excluded':derivatives,'whole_consumer_function_recovered':False,'installed_build_unchanged':True,'target_runtime_executed':False,'live_process_access':False,'whole_product_completion_percent':None,'limits':['Full 0x4134ab40 control flow,cache population,engine callback and its callers are incomplete.','Selector enum names are unverified; numeric IDs are preserved.','Standalone tests use authored cache fixtures and ordinary masked floating-point behavior.','The observed write tail is not included in the selector model or claimed as fully connected through every preceding path.','Conditional Ghidra derivatives remain incomplete hypotheses and are excluded from the recovered slice.']}
(out/'verification.json').write_text(json.dumps(result,indent=2))
(out/'selected-contracts.asm.txt').write_text('\n'.join(r['va']+' '+r['bytes']+' '+r['instruction'] for r in selected)+'\n')
print(json.dumps({'passed':True,'original_instruction_contracts':len(selected),'semantic_checks':tests['semantic_checks'],'whole_function_recovered':False,'installed_build_unchanged':True}))
