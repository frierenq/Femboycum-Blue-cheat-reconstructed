"""Read-only static runtime probe. Never maps or executes target code."""
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

import hashlib, json, re, struct

ROOT = Path(os.environ["FC_RESEARCH_WORKSPACE_ROOT"])
SOURCE = Path(os.environ["FC_RESEARCH_CORE"])
BASE = 0x412a0000
EXPECTED = '682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
data = SOURCE.read_bytes()
assert hashlib.sha256(data).hexdigest() == EXPECTED
pattern = re.compile(rb'luajit|lua[_ .-]|lua51|lua5\.|lj_[a-z]|dynasm|ffi[._ ]|cdata|ctype|LUAJIT', re.I)
strings = []
for match in re.finditer(rb'[\x20-\x7e]{4,}', data):
    value = match.group()
    if pattern.search(value):
        strings.append({'offset': hex(match.start()), 'va_flat': hex(BASE + match.start()),
                        'bytes': len(value), 'text': value[:2000].decode('ascii')})
result = {'source': str(SOURCE), 'sha256': EXPECTED, 'bytes': len(data),
          'flat_base': hex(BASE), 'first_64_bytes': data[:64].hex(),
          'static_only': True, 'loaded_or_executed': False, 'strings': strings}
if data[:2] == b'MZ':
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    result['pe_offset'] = hex(pe)
    result['pe_signature'] = data[pe:pe+4].hex()
    if data[pe:pe+4] == b'PE\0\0':
        machine, sections, stamp = struct.unpack_from('<HHI', data, pe+4)
        opt = pe+24
        result['pe'] = {'machine': hex(machine), 'sections': sections, 'timestamp': stamp,
                        'magic': hex(struct.unpack_from('<H',data,opt)[0]),
                        'imagebase': hex(struct.unpack_from('<I',data,opt+28)[0]),
                        'entry_rva': hex(struct.unpack_from('<I',data,opt+16)[0]),
                        'export_directory': [hex(v) for v in struct.unpack_from('<II',data,opt+96)],
                        'import_directory': [hex(v) for v in struct.unpack_from('<II',data,opt+104)]}
out = _fc_output('static-probe.json')
out.write_text(json.dumps(result, indent=2), encoding='utf-8')
print(json.dumps({'evidence': str(out), 'matching_strings': len(strings),
                  'header': result.get('pe', result['first_64_bytes'])}, indent=2))
for item in strings:
    print(item['offset'], item['text'][:300])
