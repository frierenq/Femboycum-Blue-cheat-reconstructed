"""Hash and index supplied source dependencies without running them."""
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

import hashlib, json, re
ROOT = Path(os.environ["FC_RESEARCH_WORKSPACE_ROOT"])
SUPPLIED = Path(os.environ["FC_RESEARCH_SUPPLIED_SOURCE_DIR"])
relative_inputs = ['neverlose/neverlose.cpp','neverlose/neverlose.vcxproj',
    'neverlose/neverlose.rc','neverlose/fix_imports.cpp','neverlose/Requestor.cpp',
    'server/rust-server/Cargo.toml','server/rust-server/build.rs',
    'server/rust-server/src/embedded_lua.rs','libraries/open_source/ent_c.lua',
    'libraries/open_source/http.lua','libraries/open_source/csgo_weapons.lua']
result = {'static_only':True,'source_inputs':[], 'helper_inputs':[], 'ffi_source_index':[]}
for relative in relative_inputs:
    p=SUPPLIED/relative
    data=p.read_bytes()
    result['source_inputs'].append({'relative_path':relative,'bytes':len(data),
                                   'sha256':hashlib.sha256(data).hexdigest()})
for relative in ['neverlose/bins/cpuid_emu.bin','neverlose/bins/diskpas.bin',
                 'neverlose/bins/kuser_shared_data.bin','server/data/module.bin']:
    p=SUPPLIED/relative
    data=p.read_bytes()
    markers=[]
    for m in re.finditer(rb'LuaJIT|lua51\.dll|lua5[1-4]\.dll|Lua 5\.[1-4]|lua_newstate|luaL_newstate',data,re.I):
        markers.append({'offset':hex(m.start()),'marker':m.group().decode('ascii')})
    result['helper_inputs'].append({'relative_path':relative,'bytes':len(data),
                                   'sha256':hashlib.sha256(data).hexdigest(),
                                   'literal_markers':markers})
fixes=(SUPPLIED/'neverlose/fix_imports.cpp').read_text(encoding='utf-8')
active='\n'.join(line.split('//',1)[0] for line in fixes.splitlines())
result['active_fix_imports_modules']=sorted(set(re.findall(r'L"([^"]+\.dll)"',active,re.I)))
result['active_fix_imports_lua_identifiers']=re.findall(r'\b(?:lua\w*|lj_\w*|ffi\w*)\b',active,re.I)
for p in sorted((SUPPLIED/'libraries/open_source').glob('*.lua')):
    text=p.read_text(encoding='utf-8',errors='replace')
    methods=sorted(set(re.findall(r'\bffi\.([A-Za-z_]+)',text)))
    conventions=sorted(set(re.findall(r'__(?:thiscall|fastcall|stdcall|cdecl)',text)))
    if methods or conventions:
        result['ffi_source_index'].append({'relative_path':str(p.relative_to(SUPPLIED)),
                                          'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),
                                          'ffi_members':methods,'calling_conventions':conventions})
out=_fc_output('source-evidence.json')
out.write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps({'evidence':str(out),'ffi_related_files':len(result['ffi_source_index']),
                  'active_import_modules':result['active_fix_imports_modules'],
                  'helper_markers':[{'file':i['relative_path'],'markers':i['literal_markers']} for i in result['helper_inputs']]},indent=2))
