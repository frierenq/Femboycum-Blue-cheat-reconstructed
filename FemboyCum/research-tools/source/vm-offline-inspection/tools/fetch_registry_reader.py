
import sys
sys.dont_write_bytecode = True
if not __debug__: raise RuntimeError("Python -O disables assertions")
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

import argparse
import hashlib
import io
import json
import os
import urllib.request
import zipfile

parser=argparse.ArgumentParser(description='Fetch the pinned pure-Python registry reader into scratch WORK')
parser.add_argument('--work',type=Path,default=os.environ.get('FC_VM_OFFLINE_WORK'),
                    help='scratch WORK directory (or FC_VM_OFFLINE_WORK); required')
args=parser.parse_args()
if args.work is None or not args.work.is_absolute():
    parser.error('--work must be an absolute scratch directory')
root=_fc_checked_output(args.work)
url='https://files.pythonhosted.org/packages/f1/0f/2605f98bb9c7ef92f926fdf3295583363fe42fc6e8f64cf38b24a029e767/python_registry-1.3.1-py3-none-any.whl'
sha='b5b8ae07c271dce12dacd24e16af8aa8d56167ebdb360112a4f152b6d04a4ca9'
data=urllib.request.urlopen(url,timeout=30).read()
assert hashlib.sha256(data).hexdigest()==sha
destination=root/'libs'
destination.mkdir(parents=True,exist_ok=True)
files=[]
with zipfile.ZipFile(io.BytesIO(data)) as archive:
    for entry in archive.infolist():
        if entry.is_dir():continue
        target=(destination/entry.filename).resolve()
        assert target.is_relative_to(destination.resolve())
        content=archive.read(entry)
        if target.exists():assert target.read_bytes()==content
        else:
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(content)
        files.append({'path':entry.filename,'sha256':hashlib.sha256(content).hexdigest()})
(root/'registry-reader-provenance.json').write_text(json.dumps({
    'project':'https://github.com/williballenthin/python-registry',
    'version':'1.3.1','distribution_url':url,'wheel_sha256':sha,'files':files,
    'scope':'Optional read-only offline guest-hive analysis tooling, not replacement build input'
},indent=2)+'\n',encoding='utf-8')
print('Verified and unpacked python-registry1.3.1 pure Python wheel:',len(files),'files')
