"""Static candidate index for reset references; never runs target code."""
import sys
sys.dont_write_bytecode = True
if not __debug__: raise RuntimeError("Python -O disables assertions")

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

import hashlib, json, struct

CORE=Path(os.environ["FC_RESEARCH_CORE"])
raw=CORE.read_bytes()
sha=hashlib.sha256(raw).hexdigest()
assert sha=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
base=0x412a0000; target=0x415debd0
needles={
    'absolute':target,
    'relative_to_mapped_base':target-base,
    'relative_to_0x41000000':target-0x41000000,
    'relative_to_0x40000000':target-0x40000000,
    'bitwise_not_absolute':(~target)&0xffffffff,
}
hits={}
for kind,value in needles.items():
    needle=struct.pack('<I',value)
    addresses=[];offset=0
    while True:
        offset=raw.find(needle,offset)
        if offset<0:break
        addresses.append(hex(base+offset));offset+=1
    hits[kind]={'word':hex(value),'occurrences':addresses}
report={'core_sha256':sha,'target':hex(target),'scope':'Raw byte-pattern leads only; candidate words can be data and absence does not exclude computed or external references.','candidate_word_hits':hits}
_fc_output('reference-leads.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps(report,indent=2))
