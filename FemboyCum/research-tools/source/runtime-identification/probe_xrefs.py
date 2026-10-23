"""Bounded flat-image pointers/disassembly; no native target execution."""
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
    public_tree = Path(__file__).resolve().parents[2]
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

import hashlib, json, re, struct, sys
ROOT = Path(os.environ["FC_RESEARCH_WORKSPACE_ROOT"])
sys.path.insert(0, str(Path(os.environ["FC_RESEARCH_PYTHON_LIBS"])))
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
data = Path(os.environ["FC_RESEARCH_CORE"]).read_bytes()
assert hashlib.sha256(data).hexdigest() == '682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
base = 0x412a0000
cs = Cs(CS_ARCH_X86, CS_MODE_32)
result = {'flat_base': hex(base), 'static_only': True, 'evidence': []}
for text in [b'LuaJIT 2.1.0-beta3', b'Lua 5.1', b'DynASM 1.5.0', b'cdata<%s>: %p',
             b'ctype<%s>', b'cdef', b'metatype', b'version_num', b'ffi', b'jit',
             b'__thiscall', b'__fastcall', b'__stdcall']:
    positions = [m.start() for m in re.finditer(re.escape(text)+b'\0', data)]
    entry = {'text': text.decode(), 'occurrences': []}
    for pos in positions:
        addr = base+pos
        pointers = [m.start() for m in re.finditer(re.escape(struct.pack('<I',addr)), data)]
        occurrence = {'offset': hex(pos), 'va': hex(addr), 'pointer_candidates': []}
        for off in pointers[:40]:
            start = max(0,off-8)
            occurrence['pointer_candidates'].append({'offset': hex(off), 'va': hex(base+off),
                'context_bytes': data[start:off+32].hex(),
                'linear_disassembly_unaligned': [{'address':hex(i.address),'instruction':i.mnemonic+' '+i.op_str}
                                                 for i in cs.disasm(data[start:off+32],base+start)]})
        entry['occurrences'].append(occurrence)
    result['evidence'].append(entry)
out = _fc_output('xref-probe.json')
out.write_text(json.dumps(result,indent=2),encoding='utf-8')
selected = []
for start, end in [(0x41b54a70,0x41b54aa8),(0x41dc4590,0x41dc46d0),
                   (0x41dc1e60,0x41dc1ff0),(0x41dc0ddd,0x41dc0e03)]:
    selected.append({'start':hex(start),'end':hex(end),
                     'note':'bounded linear disassembly; module entry starts come from registration arguments, not recovered complete CFGs',
                     'instructions':[{'address':hex(i.address),'bytes':i.bytes.hex(),
                                      'instruction':i.mnemonic+' '+i.op_str}
                                     for i in cs.disasm(data[start-base:end-base],start)]})
_fc_output('selected-disassembly.json').write_text(json.dumps(selected,indent=2),encoding='utf-8')
for entry in result['evidence']:
    print(entry['text'],[(o['va'],[p['va'] for p in o['pointer_candidates']]) for o in entry['occurrences']])
for block in selected:
    print('\nBLOCK',block['start'])
    for ins in block['instructions']: print(ins['address'],ins['instruction'])
