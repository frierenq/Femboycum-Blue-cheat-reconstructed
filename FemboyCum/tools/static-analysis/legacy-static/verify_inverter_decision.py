from legacy_env import research_root, workspace_root, required_path
"""Original local inverter CFG, angle-difference and external RNG binding checks."""
from pathlib import Path
import collections,ctypes,hashlib,json,re,struct,sys
research=research_root();root=workspace_root();out=research/'antiaim-accessors'
ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
# Capstone is installed separately; no private dependency directory is used.
from capstone import Cs,CS_ARCH_X86,CS_MODE_32,CS_GRP_JUMP,CS_GRP_CALL,CS_GRP_RET
from capstone.x86_const import X86_OP_IMM,X86_OP_MEM
raw=(research/'ui-controls/nl.core.bin').read_bytes();base=0x412a0000
sha=hashlib.sha256(raw).hexdigest();assert sha=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
cs=Cs(CS_ARCH_X86,CS_MODE_32);cs.detail=True;boundaries=set()
for p in out.glob('*/*.targeted.ghidra.txt'):
    boundaries.update(int(m[1],16) for m in re.finditer(r'^([0-9a-f]{8}) ',p.read_text(),re.M))
def decode(va):return next(cs.disasm(raw[va-base:va-base+16],va))
def record(i):return {'va':hex(i.address),'core_offset':hex(i.address-base),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str}
selected=[];graphs=[]
def check(va,mnemonic,operands):
    i=decode(va);assert va in boundaries and (i.mnemonic,i.op_str)==(mnemonic,operands),(hex(va),i.mnemonic,i.op_str)
    selected.append(record(i));return i
checks={
    0x41360e34:('mov','eax, dword ptr [ecx + 0x40]'),0x41360e37:('cmp','eax, dword ptr [0x424f4b18]'),
    0x41360e3d:('jne','0x41360e78'),0x41360e48:('movss','xmm0, dword ptr [eax*4 + 0x4206da20]'),
    0x41360e78:('mov','eax, dword ptr [0x424f639c]'),0x41360e7d:('movzx','ecx, byte ptr [eax + 0x16e9c]'),
    0x41360e8a:('mov','ebp, dword ptr [eax + 0x16e94]'),0x41360e90:('mov','ecx, dword ptr [eax + 0x16e98]'),
    0x41360e98:('cmove','ebx, ebp'),0x41360e9b:('test','bl, 8'),0x41360e9e:('jne','0x41360f43'),
    0x41360f43:('cmp','byte ptr [0x424b1c9d], 0'),0x41360f4a:('je','0x41360ea4'),
    0x41360f50:('mov','edx, dword ptr [0x4223bef4]'),0x41360f58:('jle','0x41360ea4'),
    0x41360f5e:('mov','edi, dword ptr [esi + edx*4 + 0x1a4]'),0x41360f67:('cmp','edi, 1'),
    0x41360f71:('je','0x41360ea4'),0x41360f7e:('movss','xmm0, dword ptr [edx*4 + 0x4206da18]'),
    0x41360ea4:('cmp','byte ptr [eax + 0x17286], 1'),0x41360eab:('mov','edx, 0x17285'),
    0x41360eb0:('sbb','edx, 0'),0x41360eb3:('cmp','byte ptr [eax + edx], 0'),
    0x41360ec1:('cmp','byte ptr [eax + 0x170a6], 1'),0x41360ec8:('mov','edx, 0x170a5'),
    0x41360ed6:('movss','xmm0, dword ptr [0x4205ac78]'),0x41360ede:('ucomiss','xmm0, dword ptr [esi + 4]'),
    0x41360ee2:('setne','dl'),0x41360ee9:('movzx','edi, byte ptr [eax + 0x16fa4]'),
    0x41360ef0:('mov','ebp, dword ptr [eax + edi*4 + 0x16f9c]'),0x41360ef9:('setg','cl'),
    0x41360efc:('or','cl, dl'),0x41360f07:('mov','edi, dword ptr [esi]'),0x41360f09:('cmp','edi, 1'),
    0x41360f0c:('ja','0x41360f8c'),0x41360f12:('sete','al'),0x41360f15:('movss','xmm1, dword ptr [eax*4 + 0x4206da20]'),
    0x41360f1e:('movaps','xmm0, xmmword ptr [0x4205a560]'),0x41360f25:('xorps','xmm0, xmm1'),
    0x41360f2b:('cmp','ebp, 2'),0x41360f30:('movaps','xmm2, xmm1'),0x41360f35:('jne','0x41360e51'),
    0x41360f8c:('test','bl, 1'),0x41360f8f:('je','0x413610fc'),
    0x41360f95:('movss','xmm0, dword ptr [esp + 0x68]'),0x41360ff0:('call','0x42031040'),
    0x41361047:('movss','xmm0, dword ptr [esi + 0x20]'),0x4136104f:('subss','xmm1, dword ptr [esi + 0x14]'),
    0x4136105f:('call','0x41573c40'),0x4136106e:('andps','xmm0, xmmword ptr [0x4205a540]'),
    0x4136107a:('movss','xmm0, dword ptr [esi + 0x20]'),0x41361084:('addss','xmm1, dword ptr [esi + 0x14]'),
    0x41361094:('call','0x41573c40'),0x413610ad:('addss','xmm1, xmm0'),0x413610b6:('ucomiss','xmm2, xmm1'),
    0x413610b9:('jbe','0x413610c8'),0x413610bb:('movss','xmm0, dword ptr [0x4206cdf8]'),
    0x413610cb:('addss','xmm1, xmm2'),0x413610cf:('ucomiss','xmm0, xmm1'),0x413610d2:('ja','0x4136118a'),
    0x413610d8:('mov','eax, dword ptr [0x424f639c]'),0x413610dd:('movzx','ecx, byte ptr [eax + 0x16e9c]'),
    0x413610e8:('mov','ecx, dword ptr [eax + 0x16e94]'),0x413610f2:('mov','ecx, dword ptr [eax + 0x16e98]'),
    0x41361105:('cmove','ecx, dword ptr [esp + 0x14]'),0x4136110a:('test','cl, 2'),
    0x4136110f:('mov','ecx, dword ptr [esi + 0x40]'),0x41361112:('cmp','ecx, dword ptr [0x424f4b18]'),
    0x41361118:('jne','0x41361133'),0x4136111f:('test','cl, 4'),0x41361124:('mov','eax, 0x80000001'),
    0x41361129:('and','eax, dword ptr [esi + 0x10]'),0x4136112e:('cmp','eax, 1'),
    0x41361133:('cmp','byte ptr [eax + 0x16b76], 1'),0x4136113a:('mov','esi, 0x16b75'),
    0x41361149:('jmp','0x41360e45'),0x4136114e:('mov','eax, dword ptr [0x4223f428]'),
    0x41361153:('mov','eax, dword ptr [eax + 0x4d2c]'),0x4136115c:('call','0x412ea1b0'),
    0x41361161:('mov','dword ptr [esp + 4], 1'),0x41361169:('mov','dword ptr [esp], 0'),
    0x41361170:('call','0x413602b0'),0x41361177:('test','eax, eax'),0x41361179:('sete','cl'),
    0x4136117c:('movss','xmm0, dword ptr [ecx*4 + 0x4206da20]'),
    0x4136118a:('movss','xmm0, dword ptr [0x4206cdfc]'),
    0x41573c44:('movss','xmm0, dword ptr [esp + 0x40]'),0x41573d01:('movss','xmm0, dword ptr [esp + 0x44]'),
    0x41573daf:('subss','xmm0, xmm2'),0x41573caa:('call','0x42031040'),
    0x41573d58:('call','0x42031040'),0x41573e07:('call','0x42031040'),
    0x413602ec:('call','dword ptr [0x425009ac]'),0x412ea1e7:('call','dword ptr [0x424fd7b4]'),
    0x413603cc:('xorps','xmm0, xmmword ptr [edx]'),0x4136046e:('xorps','xmm0, xmmword ptr [eax]'),
    0x412ea2bc:('xorps','xmm0, xmmword ptr [edx]'),0x412ea35e:('xorps','xmm0, xmmword ptr [eax]'),
    0x4136047b:('call','dword ptr [0x421b8dfc]'),0x41360487:('call','dword ptr [0x421b8e14]'),
    0x4136048d:('mov','dword ptr [0x425009ac], eax'),
    0x412ea36b:('call','dword ptr [0x421b8dfc]'),0x412ea377:('call','dword ptr [0x421b8e14]'),
    0x412ea37d:('mov','dword ptr [0x424fd7b4], eax'),
}
for va,pair in checks.items():check(va,*pair)
for start,end in [(0x41360e20,0x41361197),(0x41573c40,0x41573e7b),
                  (0x413602b0,0x413604a4),(0x412ea1b0,0x412ea394)]:
    ins=list(cs.disasm(raw[start-base:end-base],start));assert ins[-1].address+ins[-1].size==end
    assert all(i.address in boundaries for i in ins)
    indexed={i.address:i for i in ins};queue=collections.deque([start]);seen=set();edges=[];calls=[]
    while queue:
        a=queue.popleft()
        if a in seen:continue
        assert a in indexed,hex(a)
        seen.add(a);i=indexed[a]
        if i.group(CS_GRP_CALL):calls.append(record(i))
        if i.group(CS_GRP_RET):continue
        targets=[]
        if i.group(CS_GRP_JUMP):
            assert i.operands[0].type==X86_OP_IMM,(hex(a),'unresolved indirect jump')
            targets.append((i.operands[0].imm&0xffffffff,'branch'))
        if i.mnemonic!='jmp':targets.append((a+i.size,'call fallthrough' if i.group(CS_GRP_CALL) else 'fallthrough'))
        for target,kind in targets:
            assert start<=target<end,(hex(a),hex(target))
            edges.append({'from':hex(a),'to':hex(target),'kind':kind});queue.append(target)
    assert seen==set(indexed),'Unreached linear bytes require separate review'
    graphs.append({'start':hex(start),'end_exclusive':hex(end),'instructions':[record(i) for i in ins],
        'edges':edges,'calls_not_followed':calls,'unresolved_local_branches':[],
        'scope':'Complete bounded direct control-flow index of this local body, with both conditional successors and external calls retained; not path-feasibility or program-equivalence proof.'})
# Fold only recorded literal constants and known ADD/ADC carry from the two
# string-construction blocks. This is not execution/emulation of target code.
def immediate(va):
    i=decode(va);assert va in boundaries and i.operands[-1].type==X86_OP_IMM
    selected.append(record(i));return i.operands[-1].imm&0xffffffff
def xor_words(source,key):return struct.pack('<4I',*(a^b for a,b in zip(source,key)))
key_int=[immediate(a) for a in [0x41360377,0x4136036f,0x41360397,0x4136038f]]
low=immediate(0x41360344);addition=immediate(0x4136034e);total=low+addition
assert total>0xffffffff and decode(0x41360342).op_str=='ecx, ecx'
high=(immediate(0x41360351)+1)&0xffffffff
source_int=[immediate(0x4136032a),immediate(0x41360322),total&0xffffffff,high]
key_seed=[immediate(a) for a in [0x412ea267,0x412ea25f,0x412ea287,0x412ea27f]]
seed_low=immediate(0x412ea238);lea=decode(0x412ea23d)
assert lea.mnemonic=='lea' and lea.op_str=='ecx, [eax + 0x5be5]';selected.append(record(lea))
source_seed=[immediate(0x412ea220),immediate(0x412ea218),(seed_low+lea.operands[1].mem.disp)&0xffffffff,immediate(0x412ea247)]
module_int=[immediate(0x413603dc),immediate(0x413603d4),(low+immediate(0x413603f4))&0xffffffff,immediate(0x413603fd)]
module_seed=[immediate(0x412ea2cc),immediate(0x412ea2c4),(seed_low+immediate(0x412ea2e4))&0xffffffff,immediate(0x412ea2ed)]
module_key_int=[immediate(a) for a in [0x4136041d,0x41360415,0x4136043d,0x41360435]]
module_key_seed=[immediate(a) for a in [0x412ea30d,0x412ea305,0x412ea32d,0x412ea325]]
decoded_names=[xor_words(source_int,key_int),xor_words(source_seed,key_seed),xor_words(module_int,module_key_int),xor_words(module_seed,module_key_seed)]
assert decoded_names==[b'RandomInt\0\0\0\0\0\0\0',b'RandomSeed\0\0\0\0\0\0',b'vstdlib.dll\0\0\0\0\0',b'vstdlib.dll\0\0\0\0\0']
source_path=root/'work/FemboyLose-main/neverlose/fix_imports.cpp';source=source_path.read_text()
assert re.search(r'//\{ 0x421B8DFC, L"kernel32.dll", "GetModuleHandleA"',source)
assert re.search(r'//\{ 0x421B8E14, L"kernel32.dll", "GetProcAddress"',source)
bindings={'scope':'Original folded stack strings, dynamic resolver calls and cached pointer use; no external library opened or called.',
    'module':'vstdlib.dll','bindings':[
        {'name':'RandomSeed','wrapper':'0x412ea1b0','pointer_global':'0x424fd7b4','argument_words':1,'decoded_hex':decoded_names[1].hex()},
        {'name':'RandomInt','wrapper':'0x413602b0','pointer_global':'0x425009ac','argument_words':2,'decoded_hex':decoded_names[0].hex()}],
    'module_decoded_hex':decoded_names[2].hex(),
    'resolver_source_corroboration':{'file':str(source_path),'sha256':hashlib.sha256(source_path.read_bytes()).hexdigest(),
        'kind':'Commented original-address map in supplied wrapper source, not evidence of executing that map.',
        '0x421b8dfc':'GetModuleHandleA','0x421b8e14':'GetProcAddress'},
    'external_rng_algorithm_recovered':False}
(out/'inverter-rng-bindings.json').write_text(json.dumps(bindings,indent=2))
assert struct.unpack_from('<4I',raw,0x4206da18-base)==(0x42700000,0xc2700000,0xc2700000,0x42700000)
assert struct.unpack_from('<2I',raw,0x4206cdf8-base)==(0x42700000,0xc2700000)
assert struct.unpack_from('<I',raw,0x4205ac78-base)[0]==0x7f7fffff
assert struct.unpack_from('<4I',raw,0x4205a540-base)==(0x7fffffff,)*4
assert struct.unpack_from('<4I',raw,0x4205a560-base)==(0x80000000,)*4
tests=json.loads((out/'inverter-decision-semantic-tests.json').read_text());assert tests['passed'] and tests['semantic_checks']==88
initial=json.loads((research/'ui-controls/initial-map.json').read_text())
installed=root/'outputs/FemboyLose-Build/FemboyLose-local-build/FemboyLose-local-build'
assert {n:hashlib.sha256((installed/n).read_bytes()).hexdigest() for n in initial['installed_files_before']}==initial['installed_files_before']
unique={i['va']:i for i in selected}
result={'date':'2026-10-18','passed':True,'core_sha256':sha,
    'scope':'Original local inverter decision tree, wrapped angle difference and external RNG resolver bindings',
    'selected_original_instructions':list(unique.values()),'local_control_flow_indexes':graphs,'external_rng_bindings':bindings,
    'tests':tests,'local_decision_tree_reconstructed_with_supplied_dependencies':True,
    'whole_inverter_lifecycle_recovered':False,'external_rng_algorithm_recovered':False,
    'target_runtime_executed':False,'live_process_access':False,'installed_build_unchanged':True,'whole_product_completion_percent':None,
    'limits':['The original outer update method, eligibility rules and complete global context aliases remain incomplete.',
              'The model reads supplied data through integer-key callbacks; these callbacks are not an original process memory interface or original Lua ABI.',
              'RandomSeed/RandomInt calls, seed bits, arguments and zero/nonzero decision are retained; the external vstdlib RNG algorithm and live state are not reproduced.',
              'Original configuration labels, per-entity values and state-word gameplay meanings have not been joined to registration evidence.',
              'Direct CFG closure and authored tests are not a proof of whole-program semantic equivalence or original-runtime behavior.',
              'Original stack-cookie, TLS initialization, x87/CRT exception environment, concurrency and engine lifecycle are not reproduced.']}
(out/'inverter-decision-verification.json').write_text(json.dumps(result,indent=2))
print(json.dumps({'passed':True,'original_instruction_contracts':len(unique),'complete_local_control_flow_indexes':len(graphs),
    'authored_semantic_checks':tests['semantic_checks'],'external_rng_recovered':False,'whole_inverter_lifecycle_recovered':False,'installed_build_unchanged':True}))
