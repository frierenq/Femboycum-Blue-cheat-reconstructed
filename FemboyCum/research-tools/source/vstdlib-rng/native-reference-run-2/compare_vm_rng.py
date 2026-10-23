"""Compare a captured guest-only native run with source-owned probe snapshots."""
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
    public_tree = Path(__file__).resolve().parents[3]
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

import collections
import hashlib
import json

if not __debug__:
    raise RuntimeError('This evidence verifier requires assertions; do not use python -O')

OUT=Path(os.environ["FC_RESEARCH_INPUT_DIR"])
CAPTURE=OUT/'guest-capture'
expected=json.loads((OUT/'source-expected.json').read_text(encoding='utf-8'))
preparation=json.loads((OUT/'preparation.json').read_text(encoding='utf-8'))
action_bytes=(OUT/'actions.txt').read_bytes()
assert hashlib.sha256(action_bytes).hexdigest()==preparation['actions_sha256']
assert hashlib.sha256((OUT/'source-expected.json').read_bytes()).hexdigest()==preparation['expected_sha256']
actions=action_bytes.decode('ascii').splitlines()
probe_lines=(OUT/'source-probe.txt').read_text(encoding='ascii').splitlines()
assert hashlib.sha256((OUT/'source-probe.txt').read_bytes()).hexdigest()==preparation['source_probe_stdout_sha256']
assert len(actions)==len(probe_lines)==len(expected)==preparation['actions']
raw=(CAPTURE/'native.jsonl').read_bytes()
assert len(raw)<32*1024*1024 and raw.endswith(b'\n')
actual=[json.loads(line) for line in raw.splitlines()]
assert len(actual)==len(expected),(len(actual),len(expected))
assert (CAPTURE/'exit-code.txt').read_text().strip()=='0'
counts=collections.Counter();failures=[];state_mismatches=[];nan_payload_differences=0
def word(value):
    assert isinstance(value,str) and len(value)==10 and value.startswith('0x')
    result=int(value,16);assert 0<=result<=0xffffffff
    return result
def nan(value):return value&0x7f800000==0x7f800000 and value&0x007fffff!=0
for row_index,(e,a) in enumerate(zip(expected,actual)):
    assert e['sequence']==row_index
    sequence=e['sequence'];parts=e['action'].split();kind=parts[0]
    assert e['action']==actions[sequence] and e['line']==sequence+1
    fields=probe_lines[sequence].split();assert fields[0]==kind
    source_words=[int(value) for value in fields[1:]]
    source_value=None if kind=='S' else source_words.pop(0)&0xffffffff
    assert len(source_words)==35
    seed,output,generation,*table=source_words
    assert e['authored_generation_count']==generation
    assert [int(x,16) for x in e['state_words']]==[x&0xffffffff for x in [seed,output,*table]]
    assert e['value_bits']==(None if source_value is None else f'0x{source_value:08x}')
    assert a['sequence']==sequence and a['line']==e['line'] and a['action']==kind
    inputs=[int(p,16) if p.startswith('0x') else int(p)&0xffffffff for p in parts[1:]]
    assert list(map(word,a['input_bits']))==inputs
    assert a['selected_default'] is True and a['expected_vtable'] is True
    assert (word(a['dispatch_pointer'])-word(a['default_vtable']))&0xffffffff==int(os.environ["FC_RNG_DISPATCH_DELTA"], 0)
    assert a['vstdlib_path'].casefold()==os.environ["FC_GUEST_VSTDLIB_PATH"].casefold()
    assert a['tier0_path'].casefold()==os.environ["FC_GUEST_TIER0_PATH"].casefold()
    assert word(a['mxcsr'])&~0x3f==0x1f80 and word(a['x87_control'])==0x027f
    native_state=[a['default_state_seed'],a['default_state_output'],*a['default_state_table']]
    assert len(native_state)==34
    differences=[{'word':i,'source':s,'native':n} for i,(s,n) in enumerate(zip(e['state_words'],native_state)) if word(s)!=word(n)]
    if differences:state_mismatches.append({'sequence':sequence,'action':e['action'],'differences':differences})
    else:counts['full_34_word_state_matches']+=1
    counts['actions_'+kind]+=1
    if kind=='S' or kind=='M':
        assert a['value_kind']=='none' and a['value_bits'] is None
        if kind=='M':assert word(e['value_bits'])&~0x3f==0x1f80
        continue
    assert a['value_kind']==('i32' if kind=='I' else 'f32')
    source,native=word(e['value_bits']),word(a['value_bits'])
    if kind!='I' and nan(source) and nan(native):
        counts[kind+'_nan_classification_matches']+=1
        if source!=native:
            nan_payload_differences+=1
            failures.append({'sequence':sequence,'action':e['action'],
                             'source':e['value_bits'],'native':a['value_bits'],'kind':'NaN bits'})
        else:counts[kind+'_nan_exact_bit_matches']+=1
    elif source==native:counts[kind+'_exact_value_bit_matches']+=1
    else:failures.append({'sequence':sequence,'action':e['action'],'source':e['value_bits'],'native':a['value_bits']})
report={'passed':not failures and not state_mismatches,
        'scope':'Installed hash-pinned vstdlib default stream in exact isolated VirtualBox guest; not historical core/game parity',
        'guest_uuid':os.environ["FC_RESEARCH_GUEST_UUID"],
        'actions_compared':len(actual),'seed_cases':counts['actions_S'],
        'counts':dict(counts),'state_mismatch_actions':len(state_mismatches),
        'value_mismatch_actions':len(failures),'state_mismatches':state_mismatches,
        'value_mismatches':failures,'nan_bit_mismatches':nan_payload_differences,'nan_payloads_excluded':False,
        'native_jsonl_sha256':hashlib.sha256(raw).hexdigest(),
        'source_expected_sha256':hashlib.sha256((OUT/'source-expected.json').read_bytes()).hexdigest(),
        'all_native_sse_controls_1f80':True,'all_native_x87_controls_027f':True,
        'all_result_bits_including_nan_required':True,'sticky_flags_compared':False,'native_generation_counter_claimed':False}
(_fc_output('comparison.json')).write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps({k:v for k,v in report.items() if k not in ('state_mismatches','value_mismatches')},indent=2))
raise SystemExit(not report['passed'])
