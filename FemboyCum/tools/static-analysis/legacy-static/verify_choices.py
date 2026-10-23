from legacy_env import research_root, workspace_root, required_path
from pathlib import Path
import ctypes,hashlib,json,re,struct,sys
root=workspace_root();research=research_root();out=research/'choice-controls'
ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
# Capstone is installed separately; no private dependency directory is used.
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
raw=(research/'ui-controls/nl.core.bin').read_bytes();base=0x412a0000
assert hashlib.sha256(raw).hexdigest()=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
cs=Cs(CS_ARCH_X86,CS_MODE_32);boundaries=set();functions=set()
for p in out.glob('*/*.targeted.ghidra.txt'):
 text=p.read_text();boundaries.update(int(m[1],16) for m in re.finditer(r'^([0-9a-f]{8}) ',text,re.M));functions.update(m[1] for m in re.finditer(r'^FUNCTION ([0-9a-f]{8})$',text,re.M))
checks={
 0x412e461c:('js','0x412e464d'),0x412e4620:('mov','edi, dword ptr [ecx + 0xf8]'),
 0x412e4626:('mov','ecx, dword ptr [ecx + 0xfc]'),0x412e462e:('sar','ecx, 2'),
 0x412e4633:('jbe','0x412e464d'),0x412e4646:('call','0x41b969a0'),
 0x412e4653:('mov','dword ptr [esi + 0x10], 0'),
 0x412ca994:('mov','ebx, dword ptr [ecx + 0xf8]'),0x412ca99d:('mov','eax, dword ptr [ecx + 0xfc]'),
 0x412ca9d5:('add','eax, 0x18'),0x412caa08:('call','0x41b969a0'),
 0x41bb1c19:('call','dword ptr [eax + 0x74]'),0x41bb1c1c:('mov','byte ptr [esi + 0xc4], 0'),
 0x41bb1c2c:('mov','dword ptr [esi + 0xc4], 1'),0x41bb1c36:('mov','dword ptr [esi + 0xc0], 0'),
 0x41bb1c43:('mov','dword ptr [esi + 0xc8], eax'),0x41bb1c4b:('mov','dword ptr [esi + 0xbc], 0'),
 0x41bb1c61:('mov','dword ptr [ecx + 0xbc], 0'),0x41bb1c73:('mov','eax, dword ptr [eax + 0x40]'),
 0x41bb1db8:('call','0x4202c656'),0x41bb1de0:('shl','eax, cl'),
 0x41bb1deb:('or','dword ptr [ecx + 0xc0], eax'),0x41bb1df1:('mov','dword ptr [ecx + 0xc4], 1'),
 0x41bb1e00:('or','dword ptr [ecx + 0xbc], eax'),
 0x41bad5f0:('cmp','byte ptr [ecx + 0xc4], 0'),0x41bad5fd:('lea','eax, [ecx + 0xc0]'),
 0x41bad605:('lea','eax, [ecx + 0xbc]'),0x41bad6a6:('bt','ecx, esi'),
 0x41bad7b0:('bt','ecx, eax'),0x41bad90a:('call','0x4202c656'),0x41bad935:('bt','ecx, eax'),
 0x41a76c4d:('call','0x41b57450'),0x41a76c57:('mov','edi, dword ptr [ecx + 0x44]'),
 0x41a76c5a:('cmp','edi, dword ptr [eax + 8]'),0x41a76ebb:('push','0x4223c5b0'),
 0x41a76f10:('call','0x41ae7b70'),0x41a76f25:('mov','edi, dword ptr [ecx + 0xf8]'),
 0x41a76f33:('mov','dword ptr [ecx + 0xfc], edi'),0x41a76f92:('call','0x4200c9a0'),
 0x412fe490:('mov','dword ptr [esi + 0xbc], edx'),0x412fe496:('mov','byte ptr [eax + 4], 0'),
}
checked=[]
for va,expected in checks.items():
 i=next(cs.disasm(raw[va-base:va-base+16],va));assert va in boundaries and (i.mnemonic,i.op_str)==expected,(hex(va),i.mnemonic,i.op_str,expected)
 checked.append({'va':hex(va),'core_offset':hex(va-base),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str})
u32=lambda a:struct.unpack_from('<I',raw,a-base)[0]
rtti=[]
for vt in [0x42063bb4,0x420690e4]:
 col=u32(vt-4);chd=u32(col+16);count=u32(chd+8);array=u32(chd+12)
 ancestors=[hex(u32(u32(array+n*4))) for n in range(count)]
 assert '0x4223c5b0' in ancestors
 rtti.append({'vtable':hex(vt),'locator':hex(col),'descriptor':hex(u32(col+12)),'ancestor_descriptors':ancestors})
assert u32(0x420690e4+0x74)==0x412fe440
tests=json.loads((out/'semantic-tests.json').read_text());assert tests['passed'] and tests['semantic_checks']==42
before=json.loads((research/'ui-controls/initial-map.json').read_text())['installed_files_before']
installed=root/'outputs/FemboyLose-Build/FemboyLose-local-build/FemboyLose-local-build'
after={n:hashlib.sha256((installed/n).read_bytes()).hexdigest() for n in before};assert after==before
report={'date':'2026-10-18','passed':True,'scope':'FemboyLose core choice controls,static analysis plus authored semantic projections','core_sha256':hashlib.sha256(raw).hexdigest(),'functions_exported':sorted(functions),'selected_instructions':checked,'rtti':rtti,'tests':tests,'installed_build_unchanged':True,'target_code_executed':False,'live_game_or_process_memory_access':False,'whole_product_completion_percent':None,'limits':['Lua table/iterator errors and numeric-to-index conversion are not reproduced by the model.','Only default ASCII comparison branch is modeled.','Original localization/ID registry and complete history/ABI remain external.','Owned direct update branch is modeled;aggregate/proxy updates remain partial.']}
(out/'verification.json').write_text(json.dumps(report,indent=2))
(out/'selected-contracts.asm.txt').write_text('\n'.join(r['va']+' '+r['bytes']+' '+r['instruction'] for r in checked)+'\n')
print(json.dumps({'passed':True,'contract_instructions_checked':len(checked),'semantic_checks':tests['semantic_checks'],'installed_build_unchanged':True}))
