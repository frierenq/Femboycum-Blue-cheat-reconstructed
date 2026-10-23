"""Check this source tree without reading any original reference artifact."""
import argparse
import hashlib
import json
from pathlib import Path
import re

parser = argparse.ArgumentParser()
parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
parser.add_argument("--build", type=Path, help="Optional MSVC build directory for read-tlog inspection")
args = parser.parse_args()
root = args.root.resolve()
errors = []
checked = 0
for path in root.rglob("*"):
    relative = path.relative_to(root)
    # Only root build/scratch trees are excluded. Nested research output must
    # not disappear merely because a utility called its directory "work".
    if relative.parts[0] in {"build", "work", ".git"} or "__pycache__" in relative.parts:
        continue
    if path.is_symlink():
        errors.append(f"source symlink: {relative}")
    if not path.is_file():
        continue
    checked += 1
    if path.suffix.lower() in {".bin", ".lib", ".obj", ".dll", ".exe", ".pdb", ".zip"}:
        errors.append(f"binary input: {relative}")
    if path.suffix.lower() in {".cpp", ".hpp", ".h"}:
        if re.search(r'^\s*#\s*include\s*["<](?:[a-zA-Z]:|[/\\])', path.read_text(encoding="utf-8"), re.M):
            errors.append(f"absolute include: {relative}")
manifest = json.loads((root / "recovered/PROVENANCE.json").read_text(encoding="utf-8"))
for record in manifest["files"]:
    path = root / "recovered" / record["path"]
    if hashlib.sha256(path.read_bytes()).hexdigest() != record["sha256"]:
        errors.append(f"changed recovered source: {record['path']}")
third_party_checked = 0
for pin in root.glob("third_party/*/SOURCE_MANIFEST.json"):
    vendor_root = pin.parent.resolve()
    vendor = json.loads(pin.read_text(encoding="utf-8"))
    for record in vendor["files"]:
        path = (vendor_root / record["path"]).resolve()
        if not path.is_relative_to(vendor_root):
            errors.append(f"third-party path escaped its source root: {record['path']}")
            continue
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != record["sha256"]:
            errors.append(f"changed or missing pinned third-party source: {record['path']}")
        third_party_checked += 1
tlogs = []
if args.build:
    for path in args.build.rglob("*.read.*.tlog"):
        data = path.read_bytes()
        encoding = "utf-16" if data.startswith((b"\xff\xfe", b"\xfe\xff")) else ("utf-16-le" if b"\0" in data[:64] else "utf-8")
        text = data.decode(encoding, errors="replace").lower().replace("/", "\\")
        # Compiler/SDK headers are allowed. Prior project/research inputs are not.
        forbidden = ["\\femboycum\\th\\", "\\endless-loader-research\\", "\\neverlose\\bins\\", ".bin\n"]
        if any(value in text for value in forbidden):
            errors.append(f"reference input in build read log: {path}")
        tlogs.append(str(path.relative_to(args.build)))
    if not tlogs:
        errors.append("no compiler/link read logs found")
result = {"passed": not errors, "source_files_checked": checked,
          "recovered_hashes_checked": len(manifest["files"]),
          "third_party_source_hashes_checked": third_party_checked,
          "build_read_logs_checked": len(tlogs), "errors": errors,
          "scope": "Bounded source/input check; not a compatibility or license attestation"}
print(json.dumps(result, indent=2))
raise SystemExit(bool(errors))
