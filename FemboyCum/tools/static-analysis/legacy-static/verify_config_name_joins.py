from legacy_env import research_root, workspace_root, required_path
"""Verify native configuration layouts, supplied English catalog and named option joins."""
from pathlib import Path
import ctypes,hashlib,json,re,struct,sys,zipfile
research=research_root();root=workspace_root();out=research/'antiaim-accessors'
ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
# Capstone is installed separately; no private dependency directory is used.
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
from capstone.x86_const import X86_OP_IMM
raw=(research/'ui-controls/nl.core.bin').read_bytes();base=0x412a0000
sha=hashlib.sha256(raw).hexdigest();assert sha=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
cs=Cs(CS_ARCH_X86,CS_MODE_32);cs.detail=True;boundaries=set()
for area in [out,research/'ui-controls',research/'choice-controls']:
    for p in area.glob('*/*.targeted.ghidra.txt'):
        boundaries.update(int(m[1],16) for m in re.finditer(r'^([0-9a-f]{8}) ',p.read_text(),re.M))
def decode(va):return next(cs.disasm(raw[va-base:va-base+16],va))
def record(i):return {'va':hex(i.address),'core_offset':hex(i.address-base),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str}
selected=[];streams=[]
def check(va,mnemonic,operands):
    i=decode(va);assert va in boundaries and (i.mnemonic,i.op_str)==(mnemonic,operands),(hex(va),i.mnemonic,i.op_str)
    selected.append(record(i));return i
checks={
    0x41302aed:('push','0x2a390'),0x41302af2:('call','0x41da7b7c'),
    0x41302afc:('push','0x2a390'),0x41302b01:('push','0'),0x41302b04:('call','0x4200cf20'),
    0x41302b18:('call','0x412e54d0'),0x41302b20:('mov','dword ptr [0x424f639c], eax'),
    0x412e57a0:('lea','ecx, [eax + 0x15fe0]'),0x412e57b3:('call','0x412d1e60'),
    0x412d1e77:('mov','edi, ecx'),0x412d1ee3:('mov','dword ptr [esi + 0x14], edi'),
    0x412d1eb1:('push','0xd74c30c0'),
    0x412e9fc3:('mov','byte ptr [edi + 0xbc], al'),0x412e9fc9:('mov','byte ptr [edi + 0xbe], 0'),
    0x412e9fd0:('mov','dword ptr [edi + 0xc0], 0'),0x412e9fde:('mov','byte ptr [edi + 0xc4], al'),
    0x412cf582:('mov','dword ptr [edi + 0xbc], eax'),0x412cf588:('mov','byte ptr [edi + 0xc4], 0'),
    0x412cf58f:('mov','dword ptr [edi + 0xc8], 0'),0x412cf59c:('mov','dword ptr [edi + 0xcc], eax'),
    0x412bde8c:('call','0x412cf490'),0x412bde97:('mov','dword ptr [ebx], 0x42063bb4'),
    0x41ba2d3c:('mov','dword ptr [edx + 0xc], eax'),0x41ba2d42:('mov','dword ptr [edx + 0x10], eax'),
    0x41ba2d48:('mov','dword ptr [edx + 0x14], eax'),
    0x412d2533:('mov','dword ptr [esi + 0x10], ecx'),0x412d256b:('mov','edx, dword ptr [esi + 0x10]'),
    0x412d27be:('mov','eax, dword ptr [esi + 0x10]'),0x412d28ac:('mov','eax, dword ptr [esi + 0x10]'),
    0x412d28de:('mov','edi, dword ptr [esi + 0x14]'),0x412d2932:('mov','dword ptr [eax + 4], edi'),
    0x412d294a:('mov','dword ptr [esi + 0x20], ecx'),0x412d29d5:('mov','edx, dword ptr [esi + 0x20]'),
    0x412d2799:('movaps','xmm0, xmmword ptr [0x4205aad0]'),0x412d27a0:('movups','xmmword ptr [eax], xmm0'),
    0x41b99ef3:('mov','ebx, 0x1505'),0x41b99ef8:('cmp','edx, 8'),0x41b99f01:('and','edi, 0xfffffff8'),
    0x41b99f12:('shl','ebx, 5'),0x41b99f15:('add','ebx, edx'),0x41b99f17:('movsx','edx, byte ptr [ecx]'),
    0x41b99f6f:('jne','0x41b99f10'),0x41b99f71:('and','eax, 7'),
    0x41b99f82:('shl','ebx, 5'),0x41b99f85:('add','ebx, edx'),
    0x41b99f87:('movsx','edx, byte ptr [ecx + edi]'),0x41b99f8b:('add','edx, ebx'),
    0x41b99f90:('jne','0x41b99f80'),0x41b99fa0:('mov','edx, 0x1505'),
    0x41b99fa5:('mov','dword ptr [esi + 0xc], edx'),0x41b99fec:('push','dword ptr [esi + 0xc]'),
    0x41b99fef:('call','0x41b97c70'),
    0x412f3a73:('xorps','xmm0, xmmword ptr [eax]'),0x412f3a8f:('lea','ebx, [esp + 0x20]'),
    0x412f3a94:('call','0x42033bb0'),0x412f3ab8:('call','0x4200c9a0'),
}
for va,pair in checks.items():check(va,*pair)
for start,end in [(0x41302ac0,0x41302b43),(0x412e9fbc,0x412e9fee),(0x412cf57c,0x412cf5ac),
                  (0x41b99ed5,0x41b99f94),(0x41b99fa0,0x41b99ff4)]:
    ins=list(cs.disasm(raw[start-base:end-base],start));assert ins[-1].address+ins[-1].size==end
    assert all(i.address in boundaries for i in ins)
    streams.append({'start':hex(start),'end_exclusive':hex(end),'instructions':[record(i) for i in ins]})
def key_hash(text):
    result=5381
    for byte in text.encode('utf-8'):result=(result*33+(byte if byte<128 else byte-256))&0xffffffff
    return result
catalog_document=json.loads((out/'seed-language-en.json').read_text(encoding='utf-8'));catalog=catalog_document['strings']
assert len(catalog)==838 and all(isinstance(k,str) and isinstance(v,str) for k,v in catalog.items())
by_hash={}
for key,text in catalog.items():by_hash.setdefault(key_hash(key),[]).append({'key':key,'text':text})
assert all(len(v)==1 for v in by_hash.values())
def label(identifier):
    assert identifier in by_hash
    return {'identifier':hex(identifier),**by_hash[identifier][0]}
section=0x15fe0
# Kind, section offset, key/tooltip, LEA/input stores/call and final-vtable store.
specs=[
 ('switch',0x9e8,'anti_aim_angles_body_yaw',0xa9c88f87,0x412d24fb,'edx',0x412d2515,0x412d2522,0x412d251e,0x412d2536,0x412d2541,'eax'),
 ('switch',0xad8,'anti_aim_angles_body_yaw_inverter',0x21e357f5,0x412d254b,'eax',0x412d2565,0x412d2575,0x412d2571,0x412d2589,0x412d2594,'eax'),
 ('selectable',0xdf8,'anti_aim_angles_body_yaw_options',0,0x412d27af,'eax',0x412d27b8,0x412d27d0,0x412d27c4,0x412d27e4,0x412d27ef,'eax'),
 ('combo',0xf00,'anti_aim_angles_body_yaw_freestanding',0xa4e55da0,0x412d289d,'eax',0x412d28a6,0x412d28be,0x412d28b2,0x412d28d2,None,None),
 ('switch',0x1008,'anti_aim_angles_body_yaw_freestanding',0xc5530cc3,0x412d2912,'edi',0x412d292c,0x412d2939,0x412d2935,0x412d294d,0x412d2958,'eax'),
 ('switch',0x11e8,'anti_aim_angles_freestanding_body_freestanding',0x7fc6b0a9,0x412d29b5,'eax',0x412d29cf,0x412d29df,0x412d29db,0x412d29f3,0x412d2a01,'edx'),
]
controls=[]
for kind,relative,key,tooltip,lea,base_register,key_va,tooltip_va,default_va,call,vt_va,vt_register in specs:
    identifier=key_hash(key);is_bool=kind=='switch';arg_register='eax' if is_bool else 'edx'
    check(lea,'lea',f'ecx, [{base_register} + {hex(relative)}]')
    check(key_va,'mov',f'dword ptr [{arg_register}], {hex(identifier)}')
    check(tooltip_va,'mov',f'dword ptr [{arg_register} + {"0xc" if is_bool else "0x10"}], {hex(tooltip) if tooltip else "0"}')
    check(default_va,'mov',f'{"byte" if is_bool else "dword"} ptr [{arg_register} + 8], 0')
    constructor=0x412e9ed0 if is_bool else 0x412bddc0
    check(call,'call',hex(constructor));vtable=0x4206b564 if is_bool else (0x420690e4 if kind=='selectable' else 0x42063bb4)
    if vt_va:
        destination=f'[{vt_register}]' if kind=='selectable' else f'[{vt_register} + {hex(relative)}]'
        check(vt_va,'mov',f'dword ptr {destination}, {hex(vtable)}')
    object_offset=section+relative;stored=object_offset+0xbc;override=stored+(1 if is_bool else 4)
    selector=object_offset+(0xbe if is_bool else 0xc4);default=object_offset+(0xc4 if is_bool else 0xcc)
    controls.append({'type':kind,'label':label(identifier),'tooltip':label(tooltip) if tooltip else None,
        'section_offset':hex(relative),'object_bank_offset':hex(object_offset),'stored_bank_offset':hex(stored),
        'override_bank_offset':hex(override),'override_selector_bank_offset':hex(selector),'default_bank_offset':hex(default),
        'initial_stored_and_default':0,'initial_override_and_selector':'zero in initially zero-filled bank',
        'constructor':hex(constructor),'constructor_call':hex(call),'vtable':hex(vtable)})
option_ids=struct.unpack_from('<4I',raw,0x4205aad0-base)
assert option_ids==(0x16049072,0x47fd6e39,0xddda9401,0xa2b92dc3)
options=[{'index':i,'bit':1<<i,**label(value)} for i,value in enumerate(option_ids)]
choice_ids=[]
for va,value in [(0x412d287d,0x7b878bd4),(0x412d2883,0x6195cf50),(0x412d288a,0x619c739d)]:
    i=decode(va);assert i.mnemonic=='mov' and i.operands[-1].type==X86_OP_IMM and i.operands[-1].imm&0xffffffff==value
    selected.append(record(i));choice_ids.append(value)
choices=[{'index':i,**label(value)} for i,value in enumerate(choice_ids)]
# Native virtual type names: prior combo/selectable leaves plus the new switch
# literal join. The latter's full buffer is passed to length and copy helpers.
for vt,target in [(0x4206b564,0x412f39d0),(0x42063bb4,0x4131a640),(0x420690e4,0x41302230)]:
    assert struct.unpack_from('<I',raw,vt+0x90-base)[0]==target
def immediate(va):
    i=decode(va);assert va in boundaries and i.operands[-1].type==X86_OP_IMM;selected.append(record(i));return i.operands[-1].imm&0xffffffff
source=[immediate(a) for a in [0x412f39e7,0x412f39df,0x412f3a05,0x412f39fd]]
key=[immediate(a) for a in [0x412f3a23,0x412f3a1b,0x412f3a40,0x412f3a38]]
assert struct.pack('<4I',*(a^b for a,b in zip(source,key)))==b'switch'+bytes(10)
extraction=json.loads((out/'seed-language-extraction.json').read_text(encoding='utf-8'))
english=next(x for x in extraction['languages'] if x['code']=='en')
assert hashlib.sha256(json.dumps(catalog_document,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')).hexdigest()==english['json_semantic_sha256']
assert hashlib.sha256((out/'seed-module.compressed.data').read_bytes()).hexdigest()==extraction['compressed_data_sha256']
module_source=root/'work/FemboyLose-main/server/data/module.bin';module_bytes=module_source.read_bytes()
assert extraction['module_sha256']==hashlib.sha256(module_bytes).hexdigest()
archive=required_path('FC_SOURCE_ARCHIVE')
archive_sha=hashlib.sha256(archive.read_bytes()).hexdigest();assert archive_sha=='141dc976875915776c55e2e71c8b02ce9f8f06d876b9462112eb9011957a64e3'
with zipfile.ZipFile(archive) as package:
    members=[x for x in package.infolist() if x.filename.endswith('/server/data/module.bin')]
    assert len(members)==1 and members[0].file_size==len(module_bytes)==385360
    assert package.read(members[0])==module_bytes
    archive_member=members[0].filename
tests=json.loads((out/'localization-key-semantic-tests.json').read_text());assert tests['passed'] and tests['semantic_checks']==25
decision_tests=json.loads((out/'inverter-decision-semantic-tests.json').read_text());assert decision_tests['passed'] and decision_tests['semantic_checks']==88
initial=json.loads((research/'ui-controls/initial-map.json').read_text());installed=root/'outputs/FemboyLose-Build/FemboyLose-local-build/FemboyLose-local-build'
assert {n:hashlib.sha256((installed/n).read_bytes()).hexdigest() for n in initial['installed_files_before']}==initial['installed_files_before']
bindings={'scope':'Initial native control types/layouts/identifiers joined to supplied seed-English catalog through checked signed-byte key hashing. No runtime UI state or complete schema is asserted.',
    'config_global':'0x424f639c','bank_allocation_size':'0x2a390','section_constructor':'0x412d1e60','section_bank_offset':hex(section),
    'controls':controls,'body_yaw_options':options,'body_yaw_freestanding_choices':choices,
    'catalog':{'source_module_sha256':extraction['module_sha256'],'archive_sha256':archive_sha,'archive_member':archive_member,
        'keys':len(catalog),'key_hash_collisions':0,'language':'en'},
    'names_are_original_cpp_symbols':False,'target_runtime_executed':False}
(out/'config-settings-bindings.json').write_text(json.dumps(bindings,indent=2,ensure_ascii=False),encoding='utf-8')
(out/'seed-language-key-index.json').write_text(json.dumps({'scope':'Supplied English catalog indexed with the checked native key-hash rule. Catalog-key coverage is not widget or feature coverage.',
    'entries':{hex(k):v for k,v in by_hash.items()},'target_runtime_executed':False},indent=2,ensure_ascii=False),encoding='utf-8')
unique={i['va']:i for i in selected}
result={'date':'2026-10-19','passed':True,'core_sha256':sha,'scope':bindings['scope'],
    'selected_original_instructions':list(unique.values()),'original_local_streams':streams,'bindings':bindings,
    'tests':tests,'decision_model_recheck':decision_tests,'whole_configuration_runtime_recovered':False,
    'target_runtime_executed':False,'live_process_access':False,'installed_build_unchanged':True,'whole_product_completion_percent':None,
    'limits':['The complete configuration bank, language importer, inheritance/fallback rules, Lua ABI, rendering and callback/ownership behavior are not reconstructed here.',
              'Only initial constructors, selected member reads and the supplied seed-English catalog are joined; live custom language/rename/override/config changes were not read or tested.',
              'The two Freestanding controls intentionally share one primary localization identifier in these bytes; parent relationships and tooltip identifiers distinguish them.',
              'Named option bits identify local decision branches, not a complete implementation of the corresponding gameplay features.',
              'Full outer update lifecycle, eligibility gates, external RNG, frame aliases and full resolver remain incomplete.']}
(out/'config-name-verification.json').write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding='utf-8')
print(json.dumps({'passed':True,'original_instruction_contracts':len(unique),'typed_control_joins':len(controls),
    'named_options':len(options),'named_combo_choices':len(choices),'authored_hash_checks':25,'decision_model_checks':88,
    'catalog_keys':len(catalog),'whole_configuration_runtime_recovered':False,'installed_build_unchanged':True}))
