from legacy_env import research_root, workspace_root, required_path
"""Join four named animation-state properties to original getter bodies."""
from pathlib import Path
import ctypes,hashlib,json,re,sys
research=research_root();root=workspace_root();out=research/'entity-state'
ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
# Capstone is installed separately; no private dependency directory is used.
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
raw=(research/'ui-controls/nl.core.bin').read_bytes();base=0x412a0000
assert hashlib.sha256(raw).hexdigest()=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
cs=Cs(CS_ARCH_X86,CS_MODE_32);functions={};boundaries=set()
for area in [out,research/'animation-layers']:
    for p in area.glob('*/*.targeted.ghidra.txt'):
        for block in re.split(r'(?=^FUNCTION )',p.read_text(),flags=re.M):
            if block.startswith('FUNCTION '):
                addresses=[int(m[1],16) for m in re.finditer(r'^([0-9a-f]{8}) ',block,re.M)]
                functions[int(block[9:17],16)]=addresses;boundaries.update(addresses)
def decoded(va):return next(cs.disasm(raw[va-base:va-base+16],va))
def record(i):return {'va':hex(i.address),'core_offset':hex(i.address-base),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str}
selected=[]
def check(va,mnemonic,operands):
    i=decoded(va);assert va in boundaries and (i.mnemonic,i.op_str)==(mnemonic,operands),(hex(va),i.mnemonic,i.op_str)
    selected.append(record(i));return record(i)
def edge(source,target):
    matches=[]
    for va in functions[source]:
        i=decoded(va)
        if (i.mnemonic in ('call','jmp') and i.op_str==hex(target)) or (i.mnemonic in ('mov','push') and i.op_str.split(', ')[-1]==hex(target)):
            matches.append(record(i))
    assert matches,(hex(source),hex(target));return {'source':hex(source),'target':hex(target),'instructions':matches}
rows=json.loads((out/'animation-field-tuples.json').read_text())['rows']
data=[
    # name, offset, tuple-name read, region end, direct getter/body, closure, adapter
    ('weapon_last_bone_setup',0x5c,0x41879167,0x41879bc4,0x418828e0,0x41882790,0x41883cd0,0x418ebc10),
    ('player',0x60,0x41879bc7,0x4187a61b,0x41843cf0,0x418882a0,0x419033d0,0x4187f2f0),
    ('weapon',0x64,0x4187a61e,0x4187b084,0x41821a40,0x4183dfe0,0x4182de00,0x418357a0),
    ('weapon_last',0x68,0x4187b087,0x4187bb00,0x41877580,0x418f56a0,0x41836480,0x4182ab10),
]
mapped=[];edges=[]
for name,offset,name_read,region_end,getter,body,closure,adapter in data:
    row=next(x for x in rows if x['name']==name);tuple_name=int(row['tuple_offset'],16)+4
    base_reg='ebx' if name=='weapon_last_bone_setup' else 'eax'
    check(name_read,'mov',f'eax, dword ptr [{base_reg} + {hex(tuple_name)}]')
    # Check previously recovered tuple-pointer stores against original bytes.
    for which in ['tuple_name_pointer','tuple_descriptor_pointer']:
        for step in ['lea','store']:
            r=row[which][step];i=decoded(int(r['va'],16));assert i.bytes.hex()==r['bytes'] and i.mnemonic+' '+i.op_str==r['instruction']
            selected.append(record(i))
    region=[decoded(va) for va in functions[0x41878620] if name_read<=va<region_end]
    def captures(target):
        found=[record(i) for i in region if i.mnemonic in ('push','mov') and i.op_str.split(', ')[-1]==hex(target)]
        assert found,(name,hex(target));return found
    captured={'direct_getter':captures(getter),'closure_callback':captures(closure),'readonly_setter':captures(0x4177df00)}
    check(getter,'mov','ecx, dword ptr [esp + 4]');check(getter+4,'jmp',hex(body))
    field_pushes=[decoded(va) for va in functions[getter] if decoded(va).mnemonic=='push' and decoded(va).op_str==f'dword ptr [eax + {hex(offset)}]']
    assert len(field_pushes)==1
    i=field_pushes[0];selected.append(record(i));check(i.address+i.size,'call','0x41b45ed0')
    # Capture path independently reads the same state pointer slot.
    check(adapter+0xb,'push',f'dword ptr [eax + {hex(offset)}]')
    check(adapter+0xe,'call','0x41b45ed0')
    for source,target in [(getter,0x418e4180),(getter,0x41b45ed0),(getter,0x413919a0),(closure,adapter),(closure,0x41840d50),(adapter,0x41b45ed0)]:
        edges.append(edge(source,target))
    stores=[record(decoded(va)) for va in functions[getter] if decoded(va).mnemonic=='mov' and decoded(va).op_str=='dword ptr [esi], eax']
    assert len(stores)==1;selected.extend(stores)
    mapped.append({'name':name,'tuple_offset':row['tuple_offset'],'member_offset':hex(offset),
        'kind':'native-entity-pointer projected to indexed entity userdata','direct_getter':hex(getter),'direct_body':hex(body),
        'closure_callback':hex(closure),'captured_native_adapter':hex(adapter),'readonly_setter':'0x4177df00',
        'null_pointer_conversion':-1,'returns_raw_pointer':False,'returns_nil_for_null_field':False,
        'tuple_name_read':record(decoded(name_read)),'registration_captures':captured,'direct_field_read':record(i),
        'userdata_value_store':stores[0]})
for va,mnemonic,operands in [
    (0x41b45ed7,'test','ecx, ecx'),(0x41b45ed9,'je','0x41b45ee6'),
    (0x41b45edb,'mov','eax, dword ptr [ecx + 8]'),(0x41b45ede,'add','ecx, 8'),
    (0x41b45ee1,'call','dword ptr [eax + 0x28]'),(0x41b45ee6,'mov','eax, 0xffffffff'),
    (0x41b45eeb,'mov','dword ptr [esi], eax')]:check(va,mnemonic,operands)
edges.append(edge(0x4177df00,0x421770a1))
assert raw[0x421770a1-base:].split(b'\0',1)[0]==b'cannot write to a readonly property'
initial=json.loads((research/'ui-controls/initial-map.json').read_text())
installed=root/'outputs/FemboyLose-Build/FemboyLose-local-build/FemboyLose-local-build'
after={n:hashlib.sha256((installed/n).read_bytes()).hexdigest() for n in initial['installed_files_before']}
assert after==initial['installed_files_before']
unique={i['va']:i for i in selected}
result={'date':'2026-10-18','passed':True,'core_sha256':initial['core_sha256'],
    'scope':'Four named animation-state special entity properties, their matching getter paths and readonly setter',
    'properties':mapped,'selected_original_instructions':list(unique.values()),'captured_pointer_and_call_edges':edges,
    'authored_runtime_tests_added':0,'target_runtime_executed':False,'live_process_access':False,'installed_build_unchanged':True,
    'whole_product_completion_percent':None,
    'limits':['Public invalid/wrong-userdata handling, reference lifetime and native entity virtual-call behavior are not fully reconstructed.',
              'Readonly applies to these property assignments; it does not prove returned entity objects or the full animation state are deeply immutable.',
              'Seven compound/array/preset animation-state properties and all animation update/resolver behavior remain separate work.']}
(out/'animation-special-properties.json').write_text(json.dumps(mapped,indent=2))
(out/'special-properties-verification.json').write_text(json.dumps(result,indent=2))
(out/'special-selected-contracts.asm.txt').write_text('\n'.join(i['va']+' '+i['bytes']+' '+i['instruction'] for i in unique.values())+'\n')
print(json.dumps({'passed':True,'named_special_properties':4,'original_instruction_contracts':len(unique),'callable_edges':len(edges),'runtime_tests_added':0,'installed_build_unchanged':True}))
