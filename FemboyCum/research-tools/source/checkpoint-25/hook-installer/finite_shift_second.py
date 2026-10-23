"""Second bounded masked-CL fork with first masked count fixed to zero.

This is decoded-data interpretation only. It explores one representative
first-count path; coarse abstract-state equality across first counts does not
prove concrete equivalence because a count-dependent stack word is read later.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True
if not __debug__: raise RuntimeError("Python -O disables assertions")

import os
import copy
import hashlib
import json
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


from abstract_trace import Machine, SHA, CS, X86_OP_REG

FIRST = 0x4298ca0e
SECOND = 0x42ae531c
FIRST_COUNT = 0

class Fork(Machine):
    def value(self, op):
        if op.type == X86_OP_REG and CS.reg_name(op.reg) == 'cl':
            if self.current_ins == FIRST: return FIRST_COUNT
            if self.current_ins == SECOND and hasattr(self, 'second_count'):
                return self.second_count
        return super().value(op)

base = Fork(continue_cpuid=True, instruction_limit=20000).run()
assert base.current_ins == SECOND and base.stop.startswith('unknown shift count ')
assert base.steps == 13595 and len(base.edges) == 1402
assert not base.loads
base.pc = SECOND
base.steps -= 1

results = []
for count in range(32):
    run = copy.deepcopy(base)
    run.second_count = count
    run.run()
    results.append({
        'second_masked_count': count,
        'steps': run.steps,
        'edges': len(run.edges),
        'pc': f'{run.pc:08x}',
        'stop_instruction': f'{run.current_ins:08x}',
        'stop': run.stop,
        'edge_sha256': hashlib.sha256(repr(run.edges).encode()).hexdigest(),
        'register_sha256': hashlib.sha256(repr(sorted(run.reg.items())).encode()).hexdigest(),
        'memory_sha256': hashlib.sha256(repr(sorted(run.mem.items())).encode()).hexdigest(),
        'loads': run.loads,
        'unresolved_reads': run.unresolved_reads,
    })
    print(count, run.steps, len(run.edges), f'{run.current_ins:08x}',
          run.stop, 'resolved descriptor/argument loads', len(run.loads))

_fc_output('finite-shift-second.json').write_text(
    json.dumps({'sha256': SHA, 'first': f'{FIRST:08x}',
                'first_masked_count': FIRST_COUNT,
                'second': f'{SECOND:08x}', 'results': results}, indent=2) + '\n',
    encoding='utf-8')
