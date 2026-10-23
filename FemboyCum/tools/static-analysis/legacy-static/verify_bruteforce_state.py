from legacy_env import research_root, workspace_root, required_path
"""Original Anti Bruteforce state-update tails, event-key joins and timing inputs."""
from pathlib import Path
import ctypes,hashlib,json,re,struct,sys
research=research_root();root=workspace_root();out=research/'antiaim-accessors'
ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
# Capstone is installed separately; no private dependency directory is used.
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
from capstone.x86_const import X86_OP_IMM
raw=(research/'ui-controls/nl.core.bin').read_bytes();base=0x412a0000
sha=hashlib.sha256(raw).hexdigest();assert sha=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
cs=Cs(CS_ARCH_X86,CS_MODE_32);cs.detail=True;boundaries=set()
for p in out.glob('*/*.targeted.ghidra.txt'):
    boundaries.update(int(m[1],16) for m in re.finditer(r'^([0-9a-f]{8}) ',p.read_text(),re.M))
indexed={}
for name in ['0x41570e50.overlap-cfg-leads.json','0x415a6b20.overlap-cfg-leads.json']:
    graph=json.loads((out/name).read_text())
    assert graph['core_sha256']==sha and not graph['node_limit_reached'] and not graph['whole_cfg_recovered']
    indexed.update((int(n['va'],16),n) for n in graph['nodes'])
def decode(va):return next(cs.disasm(raw[va-base:va-base+16],va))
def record(i):return {'va':hex(i.address),'core_offset':hex(i.address-base),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str}
def known(i):
    if i.address in boundaries:return
    assert i.address in indexed and indexed[i.address]['bytes']==i.bytes.hex() and indexed[i.address]['instruction']==i.mnemonic+' '+i.op_str
selected=[];streams=[]
def check(va,mnemonic,operands):
    i=decode(va);known(i);assert (i.mnemonic,i.op_str)==(mnemonic,operands),(hex(va),i.mnemonic,i.op_str)
    selected.append(record(i));return i
checks={
    0x41570f7e:('call','dword ptr [eax + 4]'),0x41570f84:('call','0x42033bb0'),
    0x41570f9a:('mov','esi, 0x1505'),0x41570fc2:('shl','edx, 5'),
    0x41570fc5:('add','edx, esi'),0x41570fc7:('movsx','esi, byte ptr [edi]'),
    0x41571032:('shl','edx, 5'),0x41571037:('movsx','esi, byte ptr [edi + eax]'),
    0x415710df:('cmp','esi, 0x364aedf4'),0x415710e5:('jne','0x41572033'),
    0x415710eb:('mov','eax, dword ptr [0x424f639c]'),0x415710f0:('cmp','byte ptr [eax + 0x16a86], 1'),
    0x415710f7:('mov','ecx, 0x16a85'),0x415710fc:('sbb','ecx, 0'),
    0x415710ff:('cmp','byte ptr [eax + ecx], 0'),0x41571103:('je','0x41572033'),
    0x415711a2:('xorps','xmm0, xmmword ptr [eax]'),0x415711af:('lea','edx, [esp + 0x10]'),
    0x415711b5:('push','0'),0x415711b7:('push','edx'),0x415711b8:('call','dword ptr [eax + 0x18]'),
    0x41571257:('pxor','xmm0, xmmword ptr [eax]'),0x41571265:('push','0'),
    0x4157126c:('call','dword ptr [eax + 0x18]'),0x41571291:('mov','dword ptr [esp + 0xc], eax'),
    0x41571319:('call','dword ptr [eax + 0x24]'),0x415715b4:('call','dword ptr [eax + 0xc]'),
    0x415715d9:('mov','dword ptr [esp + 8], eax'),0x4157166e:('push','dword ptr [esp + 0xc]'),
    0x41571672:('call','dword ptr [eax + 0x24]'),0x41571914:('call','dword ptr [eax + 0xc]'),
    0x41571917:('mov','edi, eax'),0x41571919:('mov','eax, dword ptr [0x424afd68]'),
    0x4157191e:('mov','eax, dword ptr [eax]'),0x41571f0f:('mov','ecx, dword ptr [esp + 8]'),
    0x41571f13:('test','edi, edi'),0x41571f15:('je','0x41572033'),
    0x41571f1b:('test','ecx, ecx'),0x41571f23:('cmp','ecx, eax'),
    0x41571f25:('jne','0x41572033'),0x41571f56:('call','dword ptr [eax + 0x278]'),
    0x41571f5e:('je','0x41572033'),0x41571f6e:('call','dword ptr [eax + 0x28]'),
    0x41571f73:('jle','0x41571f80'),0x41571f7b:('cmp','eax, dword ptr [ecx + 0x18]'),
    0x41571f7e:('jle','0x41571fad'),0x41571fb1:('call','dword ptr [eax + 0x28]'),
    0x41571fb4:('mov','edi, eax'),0x41571fb6:('mov','eax, dword ptr [0x42500648]'),
    0x41571fbb:('mov','ecx, dword ptr [eax + edi*4 + 0xa0]'),0x41571fc4:('je','0x41571fec'),
    0x41571fc6:('cmp','ecx, 2'),0x41571fcb:('cmp','ecx, 1'),0x41571fd0:('mov','ecx, 2'),
    0x41571fd7:('mov','ecx, 1'),0x41571fde:('xor','ecx, ecx'),
    0x41571fe0:('mov','dword ptr [eax + edi*4 + 0x1a4], ecx'),
    0x41571fe7:('mov','eax, dword ptr [0x42500648]'),0x41571fec:('mov','ecx, dword ptr [eax + edi*4 + 0x1a4]'),
    0x41571ff3:('cmp','ecx, 2'),0x41571ff8:('cmp','ecx, 1'),0x41571ffd:('test','ecx, ecx'),
    0x41572001:('push','2'),0x41572003:('push','1'),0x41572005:('call','0x413602b0'),
    0x4157200d:('mov','ecx, dword ptr [0x42500648]'),0x41572013:('mov','dword ptr [ecx + edi*4 + 0x1a4], eax'),
    0x4157201c:('mov','ecx, 1'),0x41572023:('mov','ecx, 2'),0x4157202a:('xor','ecx, ecx'),
    0x4157202c:('mov','dword ptr [eax + edi*4 + 0x1a4], ecx'),
    0x415a6c15:('cmp','byte ptr [eax + 0x16a86], 1'),0x415a6c21:('sbb','ecx, 0'),
    0x415a6c24:('cmp','byte ptr [eax + ecx], 0'),0x415a6c28:('je','0x415a7844'),
    0x415a6c2e:('movzx','ecx, byte ptr [eax + 0x16e9c]'),
    0x415a6c35:('test','byte ptr [eax + ecx*4 + 0x16e94], 8'),0x415a6c3d:('je','0x415a7844'),
    0x415a6c46:('cmp','dword ptr [eax + 0xc], 0x3f'),0x415a6c4a:('ja','0x415a7844'),
    0x415a7739:('call','0x413130e0'),0x415a773e:('test','eax, eax'),0x415a7740:('je','0x415a781d'),
    0x415a7748:('mov','eax, dword ptr [0x4223ca04]'),0x415a774d:('movss','xmm1, dword ptr [eax + 0x20]'),
    0x415a77b8:('mov','ecx, dword ptr [0x424b03d4]'),0x415a77c1:('cvtsi2ss','xmm0, dword ptr [ecx + edx]'),
    0x415a77d2:('mulss','xmm1, xmm0'),0x415a77d6:('mov','eax, dword ptr [0x424fdd80]'),
    0x415a77db:('movss','xmm0, dword ptr [eax + edi]'),0x415a77e0:('subss','xmm0, xmm1'),
    0x415a77e4:('andps','xmm0, xmmword ptr [0x4205a540]'),
    0x415a77eb:('ucomiss','xmm0, dword ptr [0x4206cdf4]'),0x415a77f2:('jae','0x415a781d'),
    0x415a77f4:('mov','eax, dword ptr [0x42500648]'),0x415a77fc:('mov','ecx, dword ptr [ecx + 0xc]'),
    0x415a77ff:('mov','edi, dword ptr [eax + ecx*4 + 0xa4]'),0x415a7808:('cmp','edi, 2'),
    0x415a780b:('ja','0x415a7814'),0x415a780d:('mov','edx, dword ptr [edi*4 + 0x420a210c]'),
    0x415a7814:('mov','dword ptr [eax + ecx*4 + 0xa4], edx'),
    0x415a781d:('mov','eax, dword ptr [0x42500648]'),0x415a7825:('mov','ecx, dword ptr [ecx + 0xc]'),
    0x415a7828:('mov','edi, dword ptr [eax + ecx*4 + 0x1a8]'),0x415a7831:('cmp','edi, 2'),
    0x415a7834:('ja','0x415a783d'),0x415a7836:('mov','edx, dword ptr [edi*4 + 0x420a210c]'),
    0x415a783d:('mov','dword ptr [eax + ecx*4 + 0x1a8], edx'),
    0x415a80bb:('push','0xdd6c43f'),0x415a80c0:('push','0xbc62981a'),0x415a80c5:('call','0x41b89800'),
    0x415a80fc:('mov','dword ptr [0x424b0020], eax'),
    0x415a8169:('push','0x4828f445'),0x415a816e:('push','0x801ee124'),0x415a8173:('call','0x41b89800'),
    0x415a8199:('mov','dword ptr [0x424b03d4], eax'),
    0x415a8233:('push','0x4f152ef8'),0x415a8238:('push','0xc28f4f37'),0x415a823d:('call','0x41b89800'),
    0x415a827e:('mov','dword ptr [0x424fdd80], eax'),
    0x41360f5e:('mov','edi, dword ptr [esi + edx*4 + 0x1a4]'),
}
for va,pair in checks.items():check(va,*pair)
for start,end in [(0x41571fad,0x41572033),(0x415a77d2,0x415a7844),
                  (0x415a6c15,0x415a6c50),(0x41571f0f,0x41571f31),(0x41571f54,0x41571f80)]:
    ins=list(cs.disasm(raw[start-base:end-base],start));assert ins[-1].address+ins[-1].size==end
    for i in ins:known(i)
    streams.append({'start':hex(start),'end_exclusive':hex(end),'instructions':[record(i) for i in ins]})
def immediate(va):
    i=decode(va);known(i);assert i.operands[-1].type==X86_OP_IMM;selected.append(record(i));return i.operands[-1].imm&0xffffffff
key=[immediate(a) for a in [0x41571151,0x41571149,0x41571171,0x41571169]]
source_user=[immediate(a) for a in [0x41571111,0x41571109,0x41571131,0x41571129]]
source_attacker=[immediate(a) for a in [0x415711c5,0x415711bd,0x415711e5,0x415711dd]]
user=struct.pack('<4I',*(a^b for a,b in zip(source_user,key)))
attacker=struct.pack('<4I',*(a^b for a,b in zip(source_attacker,key)))
assert user==b'userid'+bytes(10) and attacker==b'attacker'+bytes(8)
assert struct.unpack_from('<3I',raw,0x420a210c-base)==(1,2,1)
assert struct.unpack_from('<I',raw,0x4206cdf4-base)[0]==0x3e800000
assert struct.unpack_from('<4I',raw,0x4205a540-base)==(0x7fffffff,)*4
def hash_name(text):
    h=5381
    for c in text.encode():h=(h*33+(c if c<128 else c-256))&0xffffffff
    return h
assert hash_name('player_hurt')==0x364aedf4
matches=[]
for table,field,t,p,cache in [('DT_BaseCombatCharacter','m_hActiveWeapon',0xbc62981a,0x0dd6c43f,0x424b0020),
    ('DT_BasePlayer','m_nTickBase',0x801ee124,0x4828f445,0x424b03d4),
    ('DT_WeaponCSBase','m_fLastShotTime',0xc28f4f37,0x4f152ef8,0x424fdd80)]:
    assert hash_name(table)==t and hash_name(field)==p
    matches.append({'table_name_match':table,'table_identifier':hex(t),'property_name_match':field,
        'property_identifier':hex(p),'offset_cache':hex(cache),
        'scope':'Names match the checked signed-byte hash used elsewhere; native property-registry key construction and live engine values remain unverified.'})
tests=json.loads((out/'bruteforce-state-semantic-tests.json').read_text());assert tests['passed'] and tests['semantic_checks']==71
initial=json.loads((research/'ui-controls/initial-map.json').read_text());installed=root/'outputs/FemboyLose-Build/FemboyLose-local-build/FemboyLose-local-build'
assert {n:hashlib.sha256((installed/n).read_bytes()).hexdigest() for n in initial['installed_files_before']}==initial['installed_files_before']
unique={i['va']:i for i in selected}
result={'date':'2026-10-19','passed':True,'core_sha256':sha,
    'scope':'Bounded hurt-event and timing-selected feedback state updates, local guards and numeric/property-ID evidence',
    'selected_original_instructions':list(unique.values()),'original_local_streams':streams,
    'event_selector':{'name_hash_match':'player_hurt','hash':'0x364aedf4','handler_gate':'0x415710eb','event_fields':[user.split(b'\0')[0].decode(),attacker.split(b'\0')[0].decode()]},
    'context_projection':{'global':'0x42500648','reference_index_base':'0xa0','selected_index_base':'0x1a4',
        'feedback_reference_base':'0xa4','feedback_selected_base':'0x1a8','record_to_entity_index_adjustment':1,
        'feedback_table':{'address':'0x420a210c','entries':[1,2,1],'unsigned_input_above_2':0}},
    'timing_source_hash_matches':matches,'tests':tests,
    'whole_anti_bruteforce_lifecycle_recovered':False,'external_rng_algorithm_recovered':False,
    'target_runtime_executed':False,'live_process_access':False,'installed_build_unchanged':True,'whole_product_completion_percent':None,
    'limits':['Both containing functions have unresolved original control flow and opaque guards; no whole event/update function recovery is claimed.',
              'Hurt-state inputs assume the relevant gates and second virtual index callback have been reached; the two index calls are not collapsed into a proven stable value.',
              'Feedback inputs assume outer Body Yaw/option/index/other eligibility conditions; the original record index is re-read later and full alias/lifetime behavior remains incomplete.',
              'The virtual predicate at attacker vtable +0x278 and engine user-ID/entity/handle callbacks remain opaque and are never invoked.',
              'The timing property names are explicit hash matches; full engine property-registry construction and live field/clock identities are not proven.',
              'Original x87/SSE exception delivery/status, engine concurrency and external RNG algorithm/state are not reproduced.',
              'Reset/lifetime paths, full target selection and complete opponent resolver remain open.']}
(out/'bruteforce-state-verification.json').write_text(json.dumps(result,indent=2))
print(json.dumps({'passed':True,'original_instruction_contracts':len(unique),'original_local_streams':len(streams),
    'authored_semantic_checks':71,'whole_anti_bruteforce_lifecycle_recovered':False,'installed_build_unchanged':True}))
