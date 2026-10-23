from legacy_env import research_root, workspace_root, required_path
from pathlib import Path
import ctypes,hashlib,json,re,struct,sys
root=workspace_root();research=research_root();out=research/'button-callbacks'
ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
# Capstone is installed separately; no private dependency directory is used.
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
raw=(research/'ui-controls/nl.core.bin').read_bytes();base=0x412a0000
assert hashlib.sha256(raw).hexdigest()=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
cs=Cs(CS_ARCH_X86,CS_MODE_32);boundaries=set();functions=set()
for path in out.glob('*/*.targeted.ghidra.txt'):
 text=path.read_text();boundaries.update(int(m[1],16) for m in re.finditer(r'^([0-9a-f]{8}) ',text,re.M));functions.update(m[1] for m in re.finditer(r'^FUNCTION ([0-9a-f]{8})$',text,re.M))
checks={
 0x41ad9a10:('mov','byte ptr [ecx + 0x7e], 1'),0x41ad9a14:('mov','ecx, dword ptr [ecx + 0xac]'),
 0x41ad9a20:('jmp','dword ptr [eax + 8]'),0x41ac5632:('call','dword ptr [eax + 0x58]'),
 0x41bbbe50:('cmp','byte ptr [ecx + 0x60], 0'),0x41bbbe59:('jmp','dword ptr [eax + 0x58]'),
 0x41aabca7:('add','ecx, 0x7e'),0x41aabcba:('call','0x412b3750'),
 0x41bbbf5f:('mov','byte ptr [ecx + 0x7e], 0'),0x41bbbe87:('mov','byte ptr [ecx + 0x7e], 0'),
 0x41b4bb0a:('call','dword ptr [eax + 0x60]'),0x41b4bb99:('cmp','byte ptr [esi + 0x7e], 0'),
 0x41b4bbac:('call','0x41b4c4e0'),0x41b4bbb1:('mov','byte ptr [esi + 0x7e], 0'),
 0x41acae09:('mov','byte ptr [edi + 0x60], 0'),0x41acae3c:('mov','dword ptr [edi + 0xac], 0'),
 0x41acae4d:('lea','edx, [edi + 0x88]'),0x41acae62:('call','eax'),
 0x41acae67:('mov','dword ptr [edi + 0xac], eax'),
 0x41aee68e:('mov','ecx, dword ptr [ecx + 0xac]'),0x41aee698:('lea','eax, [esi + 0x88]'),
 0x41aee6a8:('call','dword ptr [eax + 0x10]'),0x41aee6ab:('mov','dword ptr [esi + 0xac], 0'),
 0x41aee6b7:('call','0x41bba760'),0x41aee6c1:('call','0x41da7be0'),
 0x41af3c7e:('cmp','byte ptr [ebx + 0x7f], 0'),0x41af3dec:('call','dword ptr [eax + 0x88]'),
}
rows=[]
for va,expected in checks.items():
 i=next(cs.disasm(raw[va-base:va-base+16],va));assert va in boundaries and (i.mnemonic,i.op_str)==expected,(hex(va),i.mnemonic,i.op_str,expected)
 rows.append({'va':hex(va),'core_offset':hex(va-base),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str})
u32=lambda va:struct.unpack_from('<I',raw,va-base)[0]
slots={4:0x412a6240,0x40:0x41bbbe50,0x58:0x41ad9a10,0x60:0x412e46b0,0x84:0x41aabc60,0x88:0x41ac5630}
for offset,target in slots.items():assert u32(0x420e9724+offset)==target
assert raw[0x412a6240-base]==0xc3
tests=json.loads((out/'semantic-tests.json').read_text());assert tests['passed'] and tests['semantic_checks']==19
initial=json.loads((research/'ui-controls/initial-map.json').read_text());installed=root/'outputs/FemboyLose-Build/FemboyLose-local-build/FemboyLose-local-build'
after={n:hashlib.sha256((installed/n).read_bytes()).hexdigest() for n in initial['installed_files_before']};assert after==initial['installed_files_before']
result={'date':'2026-10-18','passed':True,'scope':'FemboyLose native button pulse/action,constructor/destructor and callback boundaries','core_sha256':initial['core_sha256'],'function_entries_exported':sorted(functions),'selected_instructions':rows,'button_vtable':'0x420e9724','checked_slots':{hex(k):hex(v) for k,v in slots.items()},'tests':tests,'installed_build_unchanged':True,'target_runtime_executed':False,'live_process_access':False,'whole_product_completion_percent':None,'limits':['Native pulse model does not implement Lua:set overload conversion/guards.','Generic callback scheduler rules were known earlier and are revalidated,not claimed as newly discovered.','Callable SBO layout,complete exception paths and userdata lifetime remain partial.','Two capture-lifetime checks validate authored std::function ownership,not the original Lua VM.']}
(out/'verification.json').write_text(json.dumps(result,indent=2))
(out/'selected-contracts.asm.txt').write_text('\n'.join(r['va']+' '+r['bytes']+' '+r['instruction'] for r in rows)+'\n')
print(json.dumps({'passed':True,'instruction_contracts':len(rows),'semantic_checks':tests['semantic_checks'],'installed_build_unchanged':True}))
