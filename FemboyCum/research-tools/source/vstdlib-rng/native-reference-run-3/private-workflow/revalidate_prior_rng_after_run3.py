"""Fresh authored-only full-state/value and cumulative-FP replay of native runs1/2."""
import sys
sys.dont_write_bytecode = True

import os
from pathlib import Path

def _fc_output_root():
    value = os.environ.get("FC_RESEARCH_OUTPUT_DIR")
    if not value or not Path(value).is_absolute():
        raise RuntimeError("set FC_RESEARCH_OUTPUT_DIR to an absolute scratch directory")
    root = Path(value).resolve(strict=True)
    if not root.is_dir():
        raise RuntimeError("FC_RESEARCH_OUTPUT_DIR must be an existing directory")
    public_tree = Path(__file__).resolve().parents[4]
    if root == public_tree or root.is_relative_to(public_tree):
        raise RuntimeError("research output cannot be inside the source candidate/public tools tree")
    if public_tree.name == "research-tools" and root.is_relative_to(public_tree.parent):
        raise RuntimeError("research output cannot be inside the public release tree")
    return root


def _fc_output(name):
    root = _fc_output_root()
    target = (root / name).resolve()
    if not target.is_relative_to(root):
        raise RuntimeError("research output path escapes scratch directory")
    return target


def _fc_checked_output(path):
    target = Path(path).resolve()
    if not target.is_relative_to(_fc_output_root()):
        raise RuntimeError("explicit output must be inside FC_RESEARCH_OUTPUT_DIR")
    return target

import hashlib
import importlib.util
import json
import subprocess

WORK=Path(os.environ["FC_RESEARCH_WORK_DIR"])
SOURCE=Path(os.environ["FC_RESEARCH_SOURCE_ROOT"])
OUT=_fc_output('prior-rng-after-run3')
OUT.mkdir(exist_ok=True)
UNIT=WORK/'foundation-build/Release/fc_uniform_random_tests.exe'
FP=OUT/'fp-build/Release/owned_rng_fp_status.exe'
RUNS={
 'run1':('vm-rng-inputs',6274,'f6cb6a50b130a47612df37bc1cdfe9c5be5fb3ab67125c7418ddcac3efa4e73d',
         'b49c831374343a633b39a3776556e71d410b8b6cbf84e0e2631519466dc51f73',
         'd6994741fde9c3ed7d044395b01ec9fb7ca1fb59625aac9dfda18be940427414'),
 'run2':('vm-rng-run2',6738,'fc9546a2c0949b9e5d1c74e087c4509869a0726ff2903021798a0b4135714a9a',
         '1a5b8dbd8683d103d111f98935d2fdb6ab69b2732005ec49591929ea87c5b740',
         'c90e5aa70a485107a96b019b43ab5e8a4da44730a03a62b03f14fa1a04fbb1fa')}
def require(ok,why):
    if not ok:raise RuntimeError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def hashes():
    return {name:sha((SOURCE/name).read_bytes()) for name in (
        'include/fc/uniform_random.hpp','src/uniform_random.cpp','src/uniform_random_exp.cpp',
        'src/uniform_random_exp_tables.inc','tests/uniform_random_tests.cpp',
        'research/vstdlib-rng/fp-status/owned_status_probe.cpp',
        'research/vstdlib-rng/fp-status/CMakeLists.txt',
        'research/vstdlib-rng/fp-status/compare_status.py')}
if not __debug__:raise RuntimeError('optimized Python refused')
require(not (OUT/'revalidation.json').exists(),'completed replay remains immutable')
before=hashes()
spec=importlib.util.spec_from_file_location('strict_cumulative_status',SOURCE/'research/vstdlib-rng/fp-status/compare_status.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
results={}
for label,(directory,total,actions_hash,native_hash,old_fp_hash) in RUNS.items():
    folder=WORK/directory
    actions=(folder/'actions.txt').read_bytes()
    native_raw=(folder/'guest-capture/native.jsonl').read_bytes()
    require(sha(actions)==actions_hash and sha(native_raw)==native_hash,'pinned archived inputs')
    lines=actions.decode('ascii').splitlines()
    native=[json.loads(line) for line in native_raw.splitlines()]
    result=subprocess.run([str(UNIT),'--probe'],input=actions,capture_output=True,check=True)
    require(not result.stderr,'authored state probe stderr')
    source=result.stdout.decode('ascii').splitlines()
    require(len(lines)==len(native)==len(source)==total,'row count')
    counts={kind:0 for kind in 'SIFEM'}
    for index,(action,row,text) in enumerate(zip(lines,native,source)):
        parts=action.split();kind=parts[0]
        inputs=[int(word,0)&0xffffffff for word in parts[1:]]
        require(row['sequence']==index and row['line']==index+1 and row['action']==kind and
                [int(word,16) for word in row['input_bits']]==inputs,'native action echo')
        words=text.split();require(words[0]==kind,'authored action echo')
        values=[int(word,10) for word in words[1:]]
        returned=None if kind=='S' else values.pop(0)
        require(len(values)==35,'authored full state shape')
        require(values[2]>=0,'authored generation instrumentation')
        observed=[values[0]&0xffffffff,values[1]&0xffffffff,*[word&0xffffffff for word in values[3:]]]
        expected=[int(row['default_state_seed'],16),int(row['default_state_output'],16),
                  *[int(word,16) for word in row['default_state_table']]]
        require(len(expected)==34 and observed==expected,'native/full-state mismatch at '+str(index))
        if kind in 'IFE':require((returned&0xffffffff)==int(row['value_bits'],16),'value bits at '+str(index))
        if kind=='M':require((returned&~0x3f)==0x1f80,'source observed controls')
        counts[kind]+=1
    state_out=OUT/(label+'-state.txt');state_out.write_bytes(result.stdout)
    fp=subprocess.run([str(FP)],input=actions,capture_output=True,check=True)
    require(not fp.stderr and sha(fp.stdout)==old_fp_hash,'cumulative FP replay changed')
    fp_out=OUT/(label+'-fp.txt');fp_out.write_bytes(fp.stdout)
    compared=module.compare(label,folder/'actions.txt',folder/'guest-capture/native.jsonl',fp_out)
    require(compared['mismatch_count']==0 and compared['rows']==total,'cumulative FP mismatch')
    (OUT/(label+'-fp-comparison.json')).write_text(json.dumps(compared,indent=2)+'\n',encoding='utf-8')
    results[label]={'rows':total,'counts':counts,'actions_sha256':actions_hash,
        'native_sha256':native_hash,'state_stdout_sha256':sha(result.stdout),
        'fp_stdout_sha256':sha(fp.stdout),'full_states_and_values_exact':True,
        'cumulative_full_fp_status_and_controls_mismatches':0}
require(hashes()==before,'source changed during replay')
receipt={'authored_only':True,'original_native_executed':False,'vm_operated':False,
    'source_sha256':before,'state_probe_exe_sha256':sha(UNIT.read_bytes()),
    'fp_probe_exe_sha256':sha(FP.read_bytes()),'runs':results,
    'scope':'Fresh source replay after run3 DIVSS/MULSS fixes against immutable runs1/2; cumulative FP only in these older captures'}
(OUT/'revalidation.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'passed':True,'rows':sum(item['rows'] for item in results.values()),'scope':receipt['scope']}))
