from legacy_env import research_root, workspace_root, required_path
"""Check original-byte naming/fallback evidence; never execute target code."""
from pathlib import Path
import ast,ctypes,hashlib,json,re,struct,sys
research=research_root();root=workspace_root();out=research/'native-consumers'
ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
# Capstone is installed separately; no private dependency directory is used.
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
from capstone.x86_const import X86_OP_IMM,X86_OP_MEM,X86_OP_REG
data=(research/'ui-controls/nl.core.bin').read_bytes();base=0x412a0000
assert hashlib.sha256(data).hexdigest()=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
cs=Cs(CS_ARCH_X86,CS_MODE_32);cs.detail=True
boundaries=set()
for p in out.glob('*/*.targeted.ghidra.txt'):
    boundaries.update(int(m[1],16) for m in re.finditer(r'^([0-9a-f]{8}) ',p.read_text(),re.M))
selected=[]
def check(va,mnemonic,operands):
    i=next(cs.disasm(data[va-base:va-base+16],va))
    assert va in boundaries and (i.mnemonic,i.op_str)==(mnemonic,operands),(hex(va),i.mnemonic,i.op_str)
    row={'va':hex(va),'core_offset':hex(va-base),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str}
    selected.append(row);return row
# Import only the bounded, abstract MOV/LEA/XOR constant evaluator.
# Fresh frame addresses describe local stack offsets, not running memory.
module=ast.parse((Path(__file__).resolve().parents[1]/'literal_evaluator.py').read_text())
fn=next(x for x in module.body if isinstance(x,ast.FunctionDef) and x.name=='analyze')
exec(compile(ast.Module(body=[fn],type_ignores=[]),'literal_evaluator.py','exec'))
slices=[]
for start,wanted in [(0x4134ac31,['jump','fall','land_light','land_heavy','ladder_climb']),
                     (0x4134be21,['_crouch']),
                     (0x4134c137,['_moving','_moving','_crouch']),
                     (0x4134cb2b,['_crouch','_moving'])]:
    d=analyze(start,data=data,base=base,cs=cs);assert [x['text'] for x in d['literals']]==wanted,(hex(start),d['literals'])
    for literal in d['literals']:
        for address,mnemonic,operands in literal['provenance']:
            check(int(address,16),mnemonic,operands)
    d['scope']='Local constant fold from original bytes; fresh abstract ESI frame, no whole-CFG or target-runtime claim.'
    (out/(hex(start)+'.literal-slice.json')).write_text(json.dumps(d,indent=2));slices.append(d)
names=[('jump',985,0x4223f430,0x4134acda),('fall',986,0x4223f418,0x4134ad61),
       ('ladder_climb',987,0x4223f2f8,0x4134aef6),('land_light',988,0x4223f370,0x4134ade8),
       ('land_heavy',989,0x4223f380,0x4134ae6f)]
selector=json.loads((out/'verification.json').read_text())
bindings=[]
for name,number,address,call in names:
    c=next(c for c in slices[0]['calls'] if int(c['at'],16)==call)
    assert c['target']=='0x4134bd70' and c['ecx']==hex(address) and c['push_arguments_in_reverse_order']==[name]
    for va,mnemonic,operands in c['recent_instructions']:check(int(va,16),mnemonic,operands)
    previous=next(c for c in selector['selector_cases'] if c['selector']==number)
    assert previous['cache_slots'][0]==hex(address)
    bindings.append({'base_name':name,'numeric_selector':number,'cache_base':hex(address),'initializer_call':hex(call),
        'slot_names':[name,name+'_moving',name+'_crouch',name+'_crouch_moving'],
        'alternate_combined_name':name+'_moving_crouch','original_cpp_enum_name_verified':False})
contracts={
    0x4134bd87:('mov','ebx, ecx'),0x4134bddd:('mov','eax, dword ptr [0x425006f8]'),
    0x4134be21:('push','dword ptr [ebp + 8]'),0x4134be24:('call','eax'),0x4134be26:('mov','dword ptr [ebx], eax'),
    0x4134be28:('mov','eax, dword ptr [0x425006f8]'),0x4134be2d:('mov','dword ptr [esi + 0xac], eax'),
    0x4134befc:('mov','dword ptr [esi + 0xbc], ebx'),
    # Concatenation helper: ECX output, stack arguments 2/3 left/right strings.
    # Three code paths move/append, move/prepend, or allocate/copy left then right.
    0x412b7a69:('mov','eax, dword ptr [esp + 0x24]'),0x412b7a6d:('mov','ebx, dword ptr [esp + 0x20]'),
    0x412b7a85:('mov','ebp, dword ptr [ebx + 0x10]'),0x412b7a8b:('mov','edi, dword ptr [eax + 0x10]'),
    0x412b7add:('add','eax, ecx'),0x412b7ae2:('call','0x4200c9a0'),
    0x412b7b6a:('lea','eax, [ecx + ebp]'),0x412b7b70:('call','0x4200c9a0'),
    0x412b7b83:('push','ebx'),0x412b7b85:('call','0x4200c9a0'),
    0x412b7bcc:('push','ebx'),0x412b7bd0:('call','0x4200c9a0'),
    0x412b7be5:('add','ebx, dword ptr [esp]'),0x412b7be9:('push','eax'),0x412b7beb:('call','0x4200c9a0'),
    # First two concatenations: input base at frame+30, suffix at frame+50.
    0x4134c075:('lea','eax, [esi + 0x50]'),0x4134c078:('mov','dword ptr [esp + 8], eax'),
    0x4134c07c:('lea','eax, [esi + 0x30]'),0x4134c07f:('mov','dword ptr [esp + 4], eax'),
    0x4134c083:('lea','ecx, [esi + 0x10]'),0x4134c086:('call','0x412b7a60'),
    0x4134c0ef:('push','edx'),0x4134c0f0:('call','dword ptr [esi + 0xac]'),
    0x4134c0f6:('mov','ecx, dword ptr [esi + 0xbc]'),0x4134c0fc:('mov','dword ptr [ecx + 8], eax'),
    0x4134c417:('lea','eax, [esi + 0x50]'),0x4134c41a:('mov','dword ptr [esp + 8], eax'),
    0x4134c41e:('mov','dword ptr [esp + 4], edi'),0x4134c422:('lea','ecx, [esi + 0x10]'),
    0x4134c425:('call','0x412b7a60'),0x4134c47e:('call','dword ptr [esi + 0xac]'),
    0x4134c484:('mov','ecx, dword ptr [esi + 0xbc]'),0x4134c48a:('mov','dword ptr [ecx + 4], eax'),
    # Combined name: base+_crouch (frame+90), then append _moving (frame+50).
    0x4134c938:('lea','eax, [esi + 0x90]'),0x4134c93e:('mov','dword ptr [esp + 8], eax'),
    0x4134c942:('lea','eax, [esi + 0x70]'),0x4134c945:('mov','dword ptr [esp + 4], eax'),
    0x4134c949:('lea','ecx, [esi + 0x30]'),0x4134c94c:('call','0x412b7a60'),
    0x4134c968:('lea','eax, [esi + 0x50]'),0x4134c96b:('mov','dword ptr [esp + 8], eax'),
    0x4134c96f:('lea','eax, [esi + 0x30]'),0x4134c972:('mov','dword ptr [esp + 4], eax'),
    0x4134c976:('lea','ecx, [esi + 0x10]'),0x4134c979:('call','0x412b7a60'),
    0x4134c9d7:('call','dword ptr [esi + 0xac]'),0x4134c9dd:('mov','ebx, dword ptr [esi + 0xbc]'),
    0x4134c9e3:('mov','dword ptr [ebx + 0xc], eax'),
    # Exact -1 tests and the single-variant fallback assignments.
    0x4134cb2b:('cmp','dword ptr [ebx + 8], -1'),0x4134cb2f:('lea','edx, [esi + 0x30]'),
    0x4134cb32:('je','0x4134cb46'),0x4134cb34:('cmp','dword ptr [ebx + 4], -1'),
    0x4134cb38:('je','0x4134cb51'),0x4134cb3a:('cmp','dword ptr [ebx + 0xc], -1'),
    0x4134cb3e:('jne','0x4134d1a6'),0x4134cb44:('jmp','0x4134cb60'),
    0x4134cb46:('mov','eax, dword ptr [ebx]'),0x4134cb48:('mov','dword ptr [ebx + 8], eax'),
    0x4134cb4b:('cmp','dword ptr [ebx + 4], -1'),0x4134cb4f:('jne','0x4134cb3a'),
    0x4134cb51:('mov','eax, dword ptr [ebx]'),0x4134cb53:('mov','dword ptr [ebx + 4], eax'),
    0x4134cb56:('cmp','dword ptr [ebx + 0xc], -1'),0x4134cb5a:('jne','0x4134d1a6'),
    # Alternate name: base+_moving (frame+90), then _crouch (frame+50).
    0x4134cf95:('lea','eax, [esi + 0x90]'),0x4134cf9b:('mov','dword ptr [esp + 8], eax'),
    0x4134cf9f:('mov','dword ptr [esp + 4], ebx'),0x4134cfa3:('lea','ecx, [esi + 0x30]'),
    0x4134cfa6:('call','0x412b7a60'),0x4134cfc2:('lea','eax, [esi + 0x50]'),
    0x4134cfc5:('mov','dword ptr [esp + 8], eax'),0x4134cfc9:('lea','eax, [esi + 0x30]'),
    0x4134cfcc:('mov','dword ptr [esp + 4], eax'),0x4134cfd0:('lea','ecx, [esi + 0x10]'),
    0x4134cfd3:('call','0x412b7a60'),0x4134d041:('call','dword ptr [esi + 0xac]'),
    0x4134d047:('mov','edi, eax'),0x4134d186:('cmp','edi, -1'),
    0x4134d189:('mov','eax, dword ptr [esi + 0xbc]'),0x4134d18f:('jne','0x4134d1a3'),
    0x4134d191:('mov','edi, dword ptr [eax + 4]'),0x4134d194:('cmp','edi, -1'),
    0x4134d197:('jne','0x4134d1a3'),0x4134d199:('mov','edi, dword ptr [eax + 8]'),
    0x4134d19c:('cmp','edi, -1'),0x4134d19f:('jne','0x4134d1a3'),
    0x4134d1a1:('mov','edi, dword ptr [eax]'),0x4134d1a3:('mov','dword ptr [eax + 0xc], edi'),
    # Lazy callback resolution ends with a dereference outside the supplied core.
    0x4134d1ea:('mov','eax, 0x51e59ef6'),0x4134d1ef:('rol','eax, 0x11'),
    0x4134d1f2:('sub','eax, 0x4374ed4b'),0x4134d1f7:('sub','eax, 0x25964b0'),
    0x4134d1fc:('xor','eax, 0x21377290'),0x4134d201:('ror','eax, 0x18'),
    0x4134d204:('xor','eax, 0x16ca12d'),0x4134d213:('mov','ecx, dword ptr [eax + 1]'),
    0x4134d216:('add','eax, ecx'),0x4134d218:('add','eax, 5'),
    0x4134d21b:('mov','dword ptr [0x425006f8], eax'),
}
for va,pair in contracts.items():check(va,*pair)
rol=lambda v,n:((v<<n)|(v>>(32-n)))&0xffffffff
v=rol(0x51e59ef6,17);v=(v-0x4374ed4b-0x25964b0)&0xffffffff;v^=0x21377290
external_site=rol(v,8)^0x16ca12d
assert external_site==0x284fe1f4 and not base<=external_site<base+len(data)
tests=json.loads((out/'cache-semantic-tests.json').read_text());assert tests['passed'] and tests['semantic_checks']==56
initial=json.loads((research/'ui-controls/initial-map.json').read_text())
installed=root/'outputs/FemboyLose-Build/FemboyLose-local-build/FemboyLose-local-build'
after={n:hashlib.sha256((installed/n).read_bytes()).hexdigest() for n in initial['installed_files_before']}
assert after==initial['installed_files_before']
unique={i['va']:i for i in selected}
result={'date':'2026-10-18','passed':True,'scope':'Base-name/cache joins and name/fallback blocks in original 0x4134bd70; not full initializer CFG or engine integration',
    'core_sha256':initial['core_sha256'],'bindings':bindings,'local_literal_slices':[{'entry':d['entry'],'literals':d['literals']} for d in slices],
    'selected_original_instructions':list(unique.values()),'tests':tests,'external_callback_relative_callsite':hex(external_site),
    'external_callback_target_resolved':False,'whole_initializer_recovered':False,'whole_consumer_recovered':False,
    'target_runtime_executed':False,'live_process_access':False,'installed_build_unchanged':True,'whole_product_completion_percent':None,
    'limits':['Guard/TLS/exception paths are incomplete; the semantic model summarizes observed naming/fallback blocks only.',
              'Numeric selectors are preserved; decoded sequence labels do not establish original C++ enum symbol names.',
              'The engine lookup implementation and rel32 operand at external stored address 0x284fe1f4 are absent from this core.',
              'Authored lookup fixtures do not establish actual runtime sequence IDs, animation correctness or resolver behavior.']}
(out/'cache-verification.json').write_text(json.dumps(result,indent=2))
(out/'sequence-cache-bindings.json').write_text(json.dumps(bindings,indent=2))
(out/'cache-selected-contracts.asm.txt').write_text('\n'.join(i['va']+' '+i['bytes']+' '+i['instruction'] for i in unique.values())+'\n')
print(json.dumps({'passed':True,'original_instruction_contracts':len(unique),'named_caches':len(bindings),'semantic_checks':tests['semantic_checks'],'installed_build_unchanged':True,'full_initializer_recovered':False}))
