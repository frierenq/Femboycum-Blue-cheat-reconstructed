from legacy_env import research_root, workspace_root, required_path
"""Verify selected native contracts against original bytes and decompiler boundaries."""
from pathlib import Path
import ctypes,hashlib,json,re,struct,sys
root=workspace_root();out=research_root()/'ui-controls'
ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
# Capstone is installed separately; no private dependency directory is used.
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
cs=Cs(CS_ARCH_X86,CS_MODE_32);cs.detail=True;base=0x412a0000
raw=(out/'nl.core.bin').read_bytes();sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
initial=json.loads((out/'initial-map.json').read_text())
assert hashlib.sha256(raw).hexdigest()==initial['core_sha256']==sha(Path(initial['core_source']))
exports=list(out.glob('*/*.targeted.ghidra.txt'));boundaries=set();functions=set()
for path in exports:
 text=path.read_text()
 boundaries.update(int(m[1],16) for m in re.finditer(r'^([0-9a-f]{8}) ',text,re.M))
 functions.update(int(m[1],16) for m in re.finditer(r'^FUNCTION ([0-9a-f]{8})$',text,re.M))
def one(va):return next(cs.disasm(raw[va-base:va-base+16],va))
def row(i):return {'va':hex(i.address),'core_offset':hex(i.address-base),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str}
checks={
 0x41abfa89:('mov','dword ptr [esi], 0x420e9ae4'),
 0x41abfa95:('mov','dword ptr [esi + 0x138], eax'),
 0x41aad384:('push','0x140'),
 0x41a82d54:('mov','dword ptr [ebp - 0x30], 0x200'),
 0x41a82d6f:('call','0x41aab960'),
 0x41a787a5:('cmp','byte ptr [ebx + 0xec], 0'),
 0x41a78803:('mov','byte ptr [ebx + 0xec], 0'),
 0x41a78839:('cmp','eax, 4'),0x41a7888b:('cmp','eax, 4'),
 0x41a78903:('call','0x41aa4c50'),
 0x41a7890e:('mov','dword ptr [eax + 0xf0], ecx'),
 0x41a789c3:('mov','dword ptr [ebx + 0xbc], esi'),
 0x41a789ea:('call','dword ptr [eax + 0x40]'),
 0x41aca2b0:('mov','eax, dword ptr [ecx + 0xf0]'),
 0x41aca2be:('call','dword ptr [eax + 0xa4]'),
 0x41af4264:('cmp','byte ptr [ecx + 0xec], 0'),
 0x41af427b:('cmp','dword ptr [ecx + 0xe4], eax'),
 0x41af42b9:('call','0x4200b31d'),
 0x41af430e:('mov','byte ptr [esi + 0xec], 0'),
 0x41accd16:('mov','ebx, dword ptr [ecx + 0x104]'),
 0x41accd2d:('lea','eax, [esi + 0xf4]'),
 0x41accd76:('mov','dword ptr [esi + 0xcc], ebx'),
 0x41accde9:('mov','byte ptr [esi + 0xec], 0'),
 0x41accdf0:('mov','ecx, dword ptr [esi + 0x78]'),
 0x41accdf9:('call','dword ptr [eax + 4]'),
 0x41accdfe:('call','0x41bbb050'),
 0x41aa0c6d:('lea','esi, [ecx + 0xf4]'),
 0x41aa0ca4:('mov','dword ptr [ecx + 0x104], edi'),
 0x41a986ee:('push','0x108d5742'),
 0x41a78485:('push','0x108d5742'),
 0x41bae5f2:('mov','edi, dword ptr [esi + 0x138]'),
 0x412bde97:('mov','dword ptr [ebx], 0x42063bb4'),
 0x41acae29:('mov','dword ptr [edi], 0x420e9724'),
 0x412c0e67:('call','0x4202c656'),
 0x412c0e87:('mov','byte ptr [ecx + 0xc4], 0'),
 0x412c0ea3:('mov','dword ptr [ecx + 0xc0], edx'),
 0x412c0ea9:('mov','dword ptr [ecx + 0xc4], 1'),
 0x412c0eb3:('mov','dword ptr [ecx + 0xc8], eax'),
 0x412c0ec7:('mov','dword ptr [ecx + 0xbc], eax'),
}
checked=[]
for va,expected in checks.items():
 i=one(va);assert va in boundaries and (i.mnemonic,i.op_str)==expected,(hex(va),row(i),expected)
 checked.append(row(i))
u32=lambda va:struct.unpack_from('<I',raw,va-base)[0]
types=[]
for name,vt,body in [('textbox',0x420e9ae4,0x41aa84c0),('combo',0x42063bb4,0x4131a640),('selectable',0x420690e4,0x41302230),('button',0x420e9724,0x41a82580)]:
 assert u32(vt+0x90)==body
 constants=[];words=[]
 for enc,mask in [(0x17,0x53),(0xf,0x4b),(0x35,0x70),(0x2d,0x68)]:
  a=one(body+enc);b=one(body+mask)
  assert a.mnemonic==b.mnemonic=='mov'
  # The textbox type leaf was previously exported;others are current exports.
  if name!='textbox':assert a.address in boundaries and b.address in boundaries
  words.append(a.operands[1].imm ^ b.operands[1].imm);constants.extend([row(a),row(b)])
 actual=struct.pack('<IIII',*words).split(b'\0',1)[0].decode('ascii');assert actual==name,(actual,name)
 types.append({'type':name,'vtable':hex(vt),'type_leaf':hex(body),'constant_instructions':constants,'slots':{hex(n):hex(u32(vt+n)) for n in [4,0x1c,0x20,0x40,0x4c,0x84,0x88,0x90,0xa4,0xac,0xb4,0xb8]}})
bindings=json.loads((out/'group-bindings.json').read_text());assert len(bindings)==21
semantic=json.loads((out/'semantic-tests.json').read_text());assert semantic['passed'] and semantic['semantic_checks']==30
installed=root/'outputs/FemboyLose-Build/FemboyLose-local-build/FemboyLose-local-build'
after={name:sha(installed/name) for name in initial['installed_files_before']}
assert after==initial['installed_files_before']
baseline=json.loads((root/'outputs/FemboyLose-Build/source_baseline.json').read_text())
assert sha(Path(baseline['archive']))==baseline['archive_sha256']
result={'date':'2026-10-18','target':'FemboyLose source snapshot plus its embedded nl.bin only','passed':True,'core_sha256':initial['core_sha256'],'method':'Read-only static decompilation and exact Capstone checks;one worker,768MiB JVM,below-normal process priority. Only authored semantic tests executed.','selected_function_entries_exported':len(functions),'checked_contract_instructions':checked,'types':types,'group_registrations':len(bindings),'semantic_tests':semantic,'installed_files_before':initial['installed_files_before'],'installed_files_after':after,'installed_build_unchanged':True,'supplied_source_zip_unchanged':True,'target_runtime_executed':False,'live_process_memory_or_game_access':False,'complete_original_source_recovered':False,'whole_product_completion_percent':None,'limits':['Semantic model is a selected state projection,not a linked replacement for nl.bin.','Full Lua ABI,ownership/history/error propagation and widget text editing remain incomplete.','Gameplay systems and original animation/resolver implementation are not recovered by this pass.']}
(out/'verification.json').write_text(json.dumps(result,indent=2))
(out/'selected-contracts.asm.txt').write_text('\n'.join(i['va']+' '+i['bytes']+' '+i['instruction'] for i in checked)+'\n')
print(json.dumps({key:result[key] for key in ['passed','selected_function_entries_exported','group_registrations','semantic_tests','installed_build_unchanged','supplied_source_zip_unchanged']},indent=2))
