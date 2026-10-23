"""Package completed offline-inspection JSON, without opening a VM or disk.

This reads only previously generated JSON and the four authored Python files.
It excludes long user-path metadata lists while retaining receipt hashes.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import os
import argparse
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


SNAPSHOT = os.environ["FC_VM_BASELINE_SNAPSHOT_UUID"]
READERS = ('vm_offline_vdi.py', 'vm_offline_ntfs.py', 'vm_offline_hives.py')

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def write(path: Path, data: bytes) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {'packaged_relative_path': str(path.relative_to(destination)).replace('\\','/'),
            'packaged_bytes': len(data), 'packaged_sha256': sha(data)}

parser = argparse.ArgumentParser()
parser.add_argument('--source-work', type=Path, required=True,
                    help='completed projectless work directory containing vm-offline')
parser.add_argument('--destination', type=Path, required=True,
                    help='source-owned research/vm-offline-inspection directory')
args = parser.parse_args()
source_work = args.source_work.resolve()
destination = _fc_checked_output(args.destination)
if not source_work.is_absolute() or not destination.is_absolute():
    parser.error('both paths must be absolute')

manifest = {
    'scope': 'selected completed baseline JSON receipts; no VM or disk access by this packaging script',
    'powered_off_snapshot_after_one_desktop_boot_and_acpi_shutdown': SNAPSHOT,
    'native_reference_executions_at_postboot_baseline': 0,
    'stages': {'preboot':'before the first desktop boot',
               'postboot':'after one desktop boot and ACPI shutdown, before native reference'},
    'source_receipts': [], 'tools': [],
}

for stage, source in (('preboot', source_work/'vm-offline'/'preboot'),
                      ('postboot', source_work/'vm-offline')):
    for name in ('disk-inventory.json','ntfs-metadata.json','startup-hives.json'):
        source_file = source/name
        raw = source_file.read_bytes()
        parsed = json.loads(raw)
        if parsed.get('passed') is not True:
            raise ValueError(f'failed source receipt: {source_file}')
        omitted = []
        if name == 'ntfs-metadata.json':
            parsed['selected_user_and_startup_metadata_count'] = len(parsed.pop('selected_user_and_startup_metadata'))
            parsed['sample_name_matches_count'] = len(parsed.pop('sample_name_matches'))
            parsed['source_receipt_sha256'] = sha(raw)
            parsed['selection_note'] = 'Path lists omitted; counts and source receipt hash retained.'
            packaged = (json.dumps(parsed, indent=2, ensure_ascii=False)+'\n').encode('utf-8')
            omitted = ['selected_user_and_startup_metadata','sample_name_matches']
        else:
            packaged = raw
        result = write(destination/'receipts'/stage/name, packaged)
        manifest['source_receipts'].append({
            'stage':stage, 'source_relative_path':str(source_file.relative_to(source_work)).replace('\\','/'),
            'source_bytes':len(raw), 'source_sha256':sha(raw),
            'omitted_fields':omitted, **result,
        })

source_file = source_work/'vm-offline'/'registry-reader-provenance.json'
raw = source_file.read_bytes()
json.loads(raw)
result = write(destination/'receipts'/'registry-reader-provenance.json',raw)
manifest['source_receipts'].append({
    'stage':'tool_provenance',
    'source_relative_path':str(source_file.relative_to(source_work)).replace('\\','/'),
    'source_bytes':len(raw),'source_sha256':sha(raw),'omitted_fields':[],**result,
})

for name in (*READERS,'fetch_registry_reader.py'):
    original = (source_work/name if name in READERS else source_work/'vm-offline'/name)
    archived = destination/'tools'/name
    manifest['tools'].append({
        'name':name,
        'original_source_relative_path':str(original.relative_to(source_work)).replace('\\','/'),
        'original_source_sha256':sha(original.read_bytes()),
        'archived_source_sha256':sha(archived.read_bytes()),
        'archived_source_relative_path':str(archived.relative_to(destination)).replace('\\','/'),
        'portability_changes_in_archived_copy':name in (*READERS,'fetch_registry_reader.py'),
    })

write(destination/'receipts'/'manifest.json',
      (json.dumps(manifest,indent=2,ensure_ascii=False)+'\n').encode('utf-8'))
print('Packaged 2 stages of completed JSON receipts; did not open VM or disk.')
