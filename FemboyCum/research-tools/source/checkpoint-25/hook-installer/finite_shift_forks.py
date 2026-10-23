"""Bounded static forks for the unknown CL shift count at 0x4298ca0e.

Only decoded pinned bytes are interpreted. Each fork represents one possible
masked x86 shift count; no original native code, module, VM, or live input is
executed or queried. Correlations with other unknown bytes are deliberately
not invented: CL remains abstract after this single instruction.
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


from abstract_trace import Machine, SHA, CS, RAW, BASE, X86_OP_REG

BOUNDARY = 0x4298ca0e

class Fork(Machine):
    def value(self, op):
        if (hasattr(self, 'shift_count') and self.current_ins == BOUNDARY and op.type == X86_OP_REG
                and CS.reg_name(op.reg) == 'cl'):
            return self.shift_count
        return super().value(op)

base = Fork(continue_cpuid=True, instruction_limit=20000).run()
assert base.stop == 'unknown shift count ?(partial cl of ?(partial write cl))', base.stop
assert base.current_ins == BOUNDARY and base.pc == BOUNDARY + 3
assert base.steps == 9322 and len(base.edges) == 953
assert not base.loads

# The failed instruction had no register/memory effects before the count test.
# Rewind its decode/step accounting and interpret it once under each possible
# CL & 31. The full CL byte is otherwise unconstrained and is not retained.
base.pc = BOUNDARY
base.steps -= 1
results = []
for count in range(32):
    run = copy.deepcopy(base)
    run.shift_count = count
    run.run()
    results.append({
        'masked_shift_count': count,
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
    print(count, run.steps, len(run.edges), run.stop,
          'descriptor/argument loads', len(run.loads))

_fc_output('finite-shift-forks.json').write_text(
    json.dumps({'sha256': SHA, 'boundary': f'{BOUNDARY:08x}', 'results': results},
               indent=2) + '\n', encoding='utf-8')
