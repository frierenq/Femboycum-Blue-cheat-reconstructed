"""Check packaged baseline receipts without opening a VM, disk, or hive."""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True
if not __debug__: raise RuntimeError("Python -O disables assertions")

import os
import ast
import hashlib
import json
from pathlib import Path

ROOT = Path(os.environ["FC_RESEARCH_ARCHIVE_ROOT"])
manifest = json.loads((ROOT/'receipts'/'manifest.json').read_text(encoding='utf-8'))
assert manifest['powered_off_snapshot_after_one_desktop_boot_and_acpi_shutdown'] == os.environ["FC_VM_BASELINE_SNAPSHOT_UUID"]
assert manifest['native_reference_executions_at_postboot_baseline'] == 0
assert len(manifest['source_receipts']) == 7

def read_checked(relative: str, expected: str) -> bytes:
    path = (ROOT/relative).resolve()
    assert path.is_relative_to(ROOT.resolve())
    data = path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == expected, relative
    return data

for receipt in manifest['source_receipts']:
    data = read_checked(receipt['packaged_relative_path'], receipt['packaged_sha256'])
    assert len(data) == receipt['packaged_bytes']
    parsed = json.loads(data)
    if receipt['stage'] in ('preboot','postboot'):
        assert parsed['passed'] is True
    if receipt['packaged_relative_path'].endswith('ntfs-metadata.json'):
        assert receipt['omitted_fields'] == ['selected_user_and_startup_metadata','sample_name_matches']
        assert not any(key in parsed for key in receipt['omitted_fields'])
        assert parsed['source_receipt_sha256'] == receipt['source_sha256']

for tool in manifest['tools']:
    source = read_checked(tool['archived_source_relative_path'],tool['archived_source_sha256'])
    ast.parse(source,filename=tool['name'])

expected = {
    'README.md','REVIEW.md',
    'tools/vm_offline_vdi.py','tools/vm_offline_ntfs.py',
    'tools/vm_offline_hives.py','tools/fetch_registry_reader.py',
    'tools/select_receipts.py','tools/verify_receipts.py',
    'receipts/manifest.json','receipts/registry-reader-provenance.json',
    *(f'receipts/{stage}/{name}' for stage in ('preboot','postboot')
      for name in ('disk-inventory.json','ntfs-metadata.json','startup-hives.json')),
}
actual = {str(path.relative_to(ROOT)).replace('\\','/')
          for path in ROOT.rglob('*') if path.is_file()}
assert actual == expected, (sorted(actual-expected),sorted(expected-actual))
print('Packaged baseline receipts, archived Python syntax, and file inventory: pass')
