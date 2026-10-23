from legacy_env import research_root, workspace_root, required_path
from pathlib import Path
import ctypes,hashlib,json,re,struct,sys
root=workspace_root();research=research_root();out=research/'value-math'
ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
# Capstone is installed separately; no private dependency directory is used.
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
raw=(research/'ui-controls/nl.core.bin').read_bytes();base=0x412a0000
assert hashlib.sha256(raw).hexdigest()=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
cs=Cs(CS_ARCH_X86,CS_MODE_32);boundaries=set();functions={}
for path in out.glob('*/*.targeted.ghidra.txt'):
 text=path.read_text()
 for block in re.split(r'(?=^FUNCTION )',text,flags=re.M):
  if not block.startswith('FUNCTION '):continue
  entry=int(block[9:17],16)
  addresses=[int(m[1],16) for m in re.finditer(r'^([0-9a-f]{8}) ',block,re.M)]
  functions[entry]=addresses;boundaries.update(addresses)
rows=[]
def decoded(va):return next(cs.disasm(raw[va-base:va-base+16],va))
def check(va,mnemonic,operands):
 i=decoded(va);assert va in boundaries and (i.mnemonic,i.op_str)==(mnemonic,operands),(hex(va),i.mnemonic,i.op_str)
 rows.append({'va':hex(va),'core_offset':hex(va-base),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str})
checks={
0x4176abc5:('mulss','xmm0, xmm0'),0x4176abd1:('addss','xmm0, xmm1'),0x4176abd9:('addss','xmm1, xmm0'),
0x4174cfd0:('sqrtss','xmm0, xmm1'),
0x41767589:('sqrtss','xmm2, xmm4'),0x4176758d:('movss','xmm3, dword ptr [0x4205a5cc]'),
0x41767595:('addss','xmm3, xmm2'),0x417675a1:('divss','xmm4, xmm3'),
0x417675ae:('movlps','qword ptr [ecx], xmm3'),0x417675b5:('movss','dword ptr [ecx + 8], xmm4'),
0x41742084:('addss','xmm2, dword ptr [0x4205a5cc]'),0x41742094:('divss','xmm3, xmm2'),
0x417420a2:('movlps','qword ptr [eax], xmm3'),0x417728e9:('mulss','xmm0, dword ptr [ecx]'),
0x41772902:('addss','xmm2, xmm0'),0x41772a36:('subps','xmm4, xmm5'),0x41772a48:('movss','dword ptr [eax + 8], xmm1'),
0x41754a22:('subss','xmm1, dword ptr [ecx + 8]'),0x41754a63:('subps','xmm0, xmm2'),0x41754a79:('sqrtss','xmm0, xmm0'),
0x4177854d:('cmpneqss','xmm5, xmm6'),0x41778568:('orps','xmm5, xmm6'),0x4177856b:('divss','xmm4, xmm5'),
0x4177859d:('movss','dword ptr [ecx], xmm1'),0x417785a5:('ucomiss','xmm1, dword ptr [0x4205a5c4]'),
0x417785ac:('jae','0x41778607'),0x417785e0:('xorps','xmm1, xmmword ptr [0x4205a560]'),
0x41778607:('ucomiss','xmm1, dword ptr [esp + 4]'),0x4177860c:('jbe','0x41778660'),
0x41778640:('xorps','xmm1, xmmword ptr [0x4205a560]'),0x417786a2:('movlps','qword ptr [ecx], xmm2'),
}
for va,expected in checks.items():check(va,*expected)

# Follow direct calls and embedded callable pointers; do not invent calling
# conventions from Ghidra's inferred C signatures.
contracts={
'lengthsqr':[(0x41769180,0x4176ce40,'call'),(0x4176ce40,0x4176abc0,'pointer'),(0x4176ce40,0x4174baa0,'call')],
'length':[(0x41763450,0x41778130,'call'),(0x41778130,0x4174cfb0,'pointer'),(0x41778130,0x4174baa0,'call')],
'length2d':[(0x41768310,0x41743520,'call'),(0x41743520,0x417437d0,'pointer')],
'length2dsqr':[(0x417786c0,0x4177a040,'call'),(0x4177a040,0x41766d10,'pointer')],
'normalize':[(0x41776ae0,0x41768980,'call'),(0x41768980,0x41767560,'pointer')],
'normalized':[(0x41755e40,0x4174d940,'pointer'),(0x4174d940,0x41742050,'pointer'),(0x4174d940,0x4174d7d0,'call')],
'dot':[(0x4176d8c0,0x41777630,'pointer'),(0x41777630,0x417728e0,'pointer'),(0x41777630,0x41755910,'call')],
'cross':[(0x41776b40,0x4176cc90,'pointer'),(0x4176cc90,0x41772a00,'pointer'),(0x4176cc90,0x4176d2e0,'call')],
'dist_to_ray':[(0x41766a70,0x41762d80,'pointer'),(0x41762d80,0x41754a10,'pointer'),(0x41762d80,0x4176a850,'call')],
'closest_ray_point':[(0x41760ac0,0x41758c10,'pointer'),(0x41758c10,0x4175ff90,'pointer'),(0x41758c10,0x41763870,'call'),(0x4175ff90,0x417784e0,'call')],
}
chains={}
for name,edges in contracts.items():
 chains[name]=[]
 for source,target,kind in edges:
  matches=[]
  for va in functions[source]:
   i=decoded(va)
   if kind=='call':accepted=i.mnemonic=='call' and i.op_str==hex(target)
   else:accepted=i.mnemonic in ('mov','push') and i.op_str.split(', ')[-1]==hex(target)
   if accepted:matches.append({'va':hex(va),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str})
  assert matches,(name,hex(source),hex(target),kind)
  chains[name].append({'source':hex(source),'target':hex(target),'kind':kind,'instructions':matches})
bindings=json.loads((out/'named-bindings.json').read_text())[1]['bindings']
assert len(bindings)==37 and len({x['name'] for x in bindings})==37
byname={x['name']:x for x in bindings}
assert byname['__len']['native_target']==byname['length']['native_target']=='0x41763450'
assert byname['closest_ray_point']['native_target']=='0x41760ac0'
for name,edges in contracts.items():assert byname[name]['native_target']==hex(edges[0][0])
constants={0x4205a554:0x3f800000,0x4205a5cc:0x34000000,0x4205a5c4:0,0x4205a560:0x80000000}
for va,bits in constants.items():assert struct.unpack_from('<I',raw,va-base)[0]==bits
tests=json.loads((out/'semantic-tests.json').read_text());assert tests['passed'] and tests['semantic_checks']==27
initial=json.loads((research/'ui-controls/initial-map.json').read_text());installed=root/'outputs/FemboyLose-Build/FemboyLose-local-build/FemboyLose-local-build'
after={n:hashlib.sha256((installed/n).read_bytes()).hexdigest() for n in initial['installed_files_before']};assert after==initial['installed_files_before']
result={'date':'2026-10-18','passed':True,'scope':'FemboyLose core vector registration,selected native arithmetic and segment projection','core_sha256':initial['core_sha256'],'function_entries_exported':[hex(x) for x in sorted(functions)],'selected_instructions':rows,'callable_chains':chains,'constants':{hex(k):{'bits':hex(v),'float':struct.unpack('<f',struct.pack('<I',v))[0]} for k,v in constants.items()},'vector_bindings_checked':len(bindings),'tests':tests,'installed_build_unchanged':True,'target_runtime_executed':False,'live_process_access':False,'whole_product_completion_percent':None,'limits':['Standalone reconstruction is not the original Lua binding ABI or recovered C++ source.','NaN payloads,denormal modes and ambient SSE flags are unverified.','Color tuples are callsite candidates until bulk-helper registration is validated.','Clamp,remaining operators,projection/render integration and gameplay math callers remain incomplete.']}
(out/'verification.json').write_text(json.dumps(result,indent=2))
(out/'selected-contracts.asm.txt').write_text('\n'.join(r['va']+' '+r['bytes']+' '+r['instruction'] for r in rows)+'\n')
print(json.dumps({'passed':True,'instruction_contracts':len(rows),'callable_edges':sum(map(len,chains.values())),'vector_bindings':len(bindings),'semantic_checks':tests['semantic_checks'],'installed_build_unchanged':True}))
