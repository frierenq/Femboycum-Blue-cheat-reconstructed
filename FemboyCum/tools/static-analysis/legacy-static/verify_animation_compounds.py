from legacy_env import research_root, workspace_root, required_path
"""Check seven typed native views; does not claim nested layout or ABI fidelity."""
from pathlib import Path
import ctypes,hashlib,json,re,struct,sys
research=research_root();root=workspace_root();out=research/'entity-state'
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
def edge(source,target):
    matches=[]
    for va in functions[source]:
        i=decoded(va)
        if (i.mnemonic in ('call','jmp') and i.op_str==hex(target)) or (i.mnemonic in ('mov','push') and i.op_str.split(', ')[-1]==hex(target)):
            matches.append(record(i))
    assert matches,(hex(source),hex(target))
    edges.append({'source':hex(source),'target':hex(target),'instructions':matches})
families=[
    # registrar, descriptor registrar, getter, view, type factory, pointer-name getter,
    # pointer-name ctor, metatable installer, unqualified-name ctor, vtable/init
    ('procedural_foot_t',0x4184c6c0,0x418e7010,0x4185f580,0x41847340,0x41820770,0x418f7680,0x41901d60,0x4190dc40,0x418df790,0x420d246c,0x418e73a2),
    ('aimmatrix_transition_t',0x418f7ec0,0x41821190,0x41897de0,0x418427b0,0x41909400,0x41822360,0x41901f30,0x418fc3d0,0x418eeb20,0x420d158c,0x41821522),
    ('animstate_pose_param_cache_t',0x4190ed00,0x41823510,0x4181e6c0,0x41825a80,0x418f4170,0x418f9580,0x418dd770,0x41877740,0x4190a0b0,0x420d24c4,0x418238a2),
    ('int',0x418ebe70,0x41891160,0x41833f50,0x41884560,0x418f8260,0x41862470,0x41899700,0x418a3ec0,0x418e6df0,0x420d1bf0,0x418914f2),
]
types=json.loads((out/'compound-native-types.json').read_text())
assert len(types['rows'])==9
for row in types['rows']:
    for r in row['selected_instructions']:
        i=decoded(int(r['va'],16));assert i.bytes.hex()==r['bytes'] and i.mnemonic+' '+i.op_str==r['instruction'];selected.append(record(i))
families_by_registrar={}
for native_type,registrar,descriptor,getter,view,factory,type_getter,type_ctor,metatable,value_ctor,vtable,init in families:
    for source,target in [(registrar,descriptor),(descriptor,getter),(descriptor,0x4181c310),
                          (view,metatable),(factory,type_getter),(type_getter,type_ctor),(metatable,value_ctor)]:
        edge(source,target)
    if native_type!='int':
        edge(getter,view);edge(view,factory)
    else:
        edge(getter,0x418e1fb0);edge(0x418e1fb0,factory);edge(0x418e1fb0,view)
    check(init,'mov',f'dword ptr [ecx], {hex(vtable)}')
    check(init+6,'mov','eax, dword ptr [eax]');check(init+8,'mov','dword ptr [ecx + 4], eax')
    assert struct.unpack_from('<I',raw,vtable-base)[0]==0x412a6440
    for constructor,wanted in [(type_ctor,native_type+' *'),(value_ctor,native_type)]:
        assert next(r for r in types['rows'] if r['constructor']==hex(constructor))['native_type']==wanted
    families_by_registrar[hex(registrar)]={'native_type':native_type,'descriptor_registrar':hex(descriptor),
        'getter':hex(getter),'view':hex(view),'descriptor_vtable':hex(vtable),
        'pointer_type_constructor':hex(type_ctor),'value_type_constructor':hex(value_ctor),'readonly_setter':'0x4181c310'}
contracts={
    0x412a6440:('lea','eax, [ecx + 4]'),
    0x4184735a:('mov','edi, dword ptr [eax]'),0x418473a9:('add','ebx, edi'),0x418473bd:('mov','dword ptr [esi], ebx'),
    0x418427ca:('mov','edi, dword ptr [eax]'),0x41842819:('add','ebx, edi'),0x4184282d:('mov','dword ptr [esi], ebx'),
    0x41825a9a:('mov','edi, dword ptr [eax]'),0x41825ae9:('add','ebx, edi'),0x41825afd:('mov','dword ptr [esi], ebx'),
    0x418e2007:('mov','ebx, dword ptr [eax]'),0x418e2014:('mov','edi, dword ptr [edi + ebx]'),
    0x418e201f:('call','0x41884560'),0x4188459f:('test','edi, edi'),0x418845a1:('je','0x418845d0'),
    0x418845bb:('call','0x418f0940'),0x418845cc:('mov','dword ptr [esi], edi'),0x418845e8:('call','0x41db9790'),
}
for va,pair in contracts.items():check(va,*pair)
edge(0x418f0940,0x418e0980)
assert next(r for r in types['rows'] if r['constructor']=='0x418e0980')['native_type']=='const int *'
rows=json.loads((out/'animation-field-tuples.json').read_text())['rows'];mapped=[]
for row in rows:
    family=families_by_registrar.get(row.get('registration_helper'))
    if not family:continue
    for r in [row['descriptor_store'],row['call'],*row['argument_instructions']]:
        i=decoded(int(r['va'],16));assert i.bytes.hex()==r['bytes'] and i.mnemonic+' '+i.op_str==r['instruction'];selected.append(record(i))
    pointer_load=row['name']=='layer_order_preset'
    mapped.append({'name':row['name'],'offset':row['member_offset'],**family,
        'value_construction':'read pointer at state+offset, nil if null; otherwise pointer-backed int userdata' if pointer_load else 'pointer-backed userdata containing state+offset',
        'pointer_storage_qualifier':'const int *' if pointer_load else family['native_type']+' *',
        'returns_lua_array_table':False,'nested_members_recovered':False,'native_extent_verified':False,'deep_mutability_verified':False,
        'existing_tuple_call':row['call']})
assert len(mapped)==7
initial=json.loads((research/'ui-controls/initial-map.json').read_text())
installed=root/'outputs/FemboyLose-Build/FemboyLose-local-build/FemboyLose-local-build'
after={n:hashlib.sha256((installed/n).read_bytes()).hexdigest() for n in initial['installed_files_before']}
assert after==initial['installed_files_before']
unique={i['va']:i for i in selected}
result={'date':'2026-10-18','passed':True,'core_sha256':initial['core_sha256'],'scope':'Seven named compound/preset getter projections and nine compiled type-name literals',
    'properties':mapped,'selected_original_instructions':list(unique.values()),'captured_pointer_and_call_edges':edges,
    'compiled_type_literals':types['rows'],'authored_runtime_tests_added':0,'target_runtime_executed':False,'live_process_access':False,
    'installed_build_unchanged':True,'whole_product_completion_percent':None,
    'limits':['This resolves the typed getter projections, not the nested member schemas, array lengths, bounds or deep mutability.',
              'In particular pose_param_mappings returns an animstate_pose_param_cache_t view, not a constructed Lua array.',
              'The int metatable name and const int pointer storage type are both preserved; their complete public indexing/mutation behavior remains open.',
              'Userdata ownership/lifetime, invalid arguments, native algorithms and original-product fidelity remain incomplete.']}
(out/'animation-compound-properties.json').write_text(json.dumps(mapped,indent=2))
(out/'compound-properties-verification.json').write_text(json.dumps(result,indent=2))
(out/'compound-selected-contracts.asm.txt').write_text('\n'.join(i['va']+' '+i['bytes']+' '+i['instruction'] for i in unique.values())+'\n')
print(json.dumps({'passed':True,'named_properties':7,'compiled_type_literals':9,'original_instruction_contracts':len(unique),'callable_edges':len(edges),'runtime_tests_added':0,'installed_build_unchanged':True}))
