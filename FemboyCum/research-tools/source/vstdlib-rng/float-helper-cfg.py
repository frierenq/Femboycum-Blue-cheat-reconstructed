"""Decode the direct CFG/data references of the installed float-power helper.

Static PE-byte inspection only; no original code is loaded or executed.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True
if not __debug__: raise RuntimeError("Python -O disables assertions")

import os
import hashlib
import json
import sys
from collections import deque
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


DLL = Path(os.environ["FC_VSTDLIB_DLL"])
LIBS = Path(os.environ["FC_RESEARCH_PYTHON_LIBS"])
SHA256 = "25af287294687ca41eb276732bb01dade88d15daccb2e8658b00775ce989538f"
BASE = 0x10000000
ENTRY = 0x10027F49
END = 0x100285FC  # First INT3 after the helper's last RET.
sys.path.insert(0, str(LIBS))
import pefile  # noqa: E402
from capstone import CS_ARCH_X86, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_MODE_32, Cs  # noqa: E402
from capstone.x86 import X86_OP_IMM, X86_OP_MEM  # noqa: E402

raw = DLL.read_bytes()
assert hashlib.sha256(raw).hexdigest() == SHA256
pe = pefile.PE(data=raw, fast_load=False)
assert pe.FILE_HEADER.Machine == 0x14C and pe.OPTIONAL_HEADER.ImageBase == BASE
cs = Cs(CS_ARCH_X86, CS_MODE_32)
cs.detail = True


def at(va: int, length: int) -> bytes:
    offset = pe.get_offset_from_rva(va - BASE)
    return raw[offset:offset + length]


pending = deque([ENTRY])
decoded = {}
out_of_function_edges = []
calls = []
fixed_data = {}
indexed_data = {}
while pending:
    address = pending.popleft()
    if address in decoded:
        continue
    assert ENTRY <= address < END, hex(address)
    ins = next(cs.disasm(at(address, 16), address))
    assert ins.address == address and ins.mnemonic != "int3", hex(address)
    next_address = address + ins.size
    successors = []
    if ins.group(CS_GRP_RET):
        pass
    elif ins.group(CS_GRP_JUMP):
        assert ins.operands[0].type == X86_OP_IMM, (hex(address), ins.op_str)
        successors.append(ins.operands[0].imm)
        if ins.mnemonic != "jmp":
            successors.append(next_address)
    else:
        successors.append(next_address)
        if ins.group(CS_GRP_CALL):
            if ins.operands[0].type == X86_OP_IMM:
                calls.append({"from": hex(address), "to": hex(ins.operands[0].imm)})
            else:
                calls.append({"from": hex(address), "to": ins.op_str})
    for successor in successors:
        if ENTRY <= successor < END:
            pending.append(successor)
        else:
            out_of_function_edges.append({"from": hex(address), "to": hex(successor)})
    memory = []
    for operand in ins.operands:
        if operand.type != X86_OP_MEM:
            continue
        mem = operand.mem
        item = {"width": operand.size, "base_register": ins.reg_name(mem.base) if mem.base else None,
                "index_register": ins.reg_name(mem.index) if mem.index else None,
                "scale": mem.scale, "displacement": hex(mem.disp & 0xFFFFFFFF)}
        memory.append(item)
        if not mem.base and 0x10030000 <= (mem.disp & 0xFFFFFFFF) < 0x10032000:
            key = hex(mem.disp & 0xFFFFFFFF)
            (indexed_data if mem.index else fixed_data).setdefault(key, []).append(hex(address))
    decoded[address] = {
        "va": hex(address), "bytes": ins.bytes.hex(), "instruction":
        ins.mnemonic + (" " + ins.op_str if ins.op_str else ""),
        "successors": [hex(value) for value in successors], "memory": memory,
    }

assert not out_of_function_edges, out_of_function_edges
assert not calls, calls
assert 0x10028136 in decoded and 0x100285FB in decoded
assert all(not (ENTRY < address < END and raw[pe.get_offset_from_rva(address-BASE)] == 0xCC)
           for address in decoded)

# The helper's indexed tables and fixed constants occupy this bounded interval.
# Pin the entire interval so future interpretation cannot silently mix builds.
TABLE_START = 0x10030A40
TABLE_END = 0x10031000
table_bytes = at(TABLE_START, TABLE_END - TABLE_START)
result = {
    "passed": True,
    "evidence_class": "direct recursive static decode of installed PE bytes",
    "dll_sha256": SHA256, "entry": hex(ENTRY), "exclusive_end": hex(END),
    "instruction_count": len(decoded),
    "reachable_instructions": [decoded[va] for va in sorted(decoded)],
    "direct_out_of_function_edges": out_of_function_edges,
    "calls": calls,
    "fixed_data_references": fixed_data,
    "indexed_data_references": indexed_data,
    "pinned_table_interval": {"start": hex(TABLE_START), "exclusive_end": hex(TABLE_END),
                              "bytes": len(table_bytes), "sha256": hashlib.sha256(table_bytes).hexdigest()},
    "native_dll_loaded": False, "original_code_executed": False,
    "limits": [
        "Direct CFG only; computed data-dependent paths and exact SSE semantics require a separate lift.",
        "The pinned interval includes helper lookup tables and constants, possibly with unused bytes.",
        "No installed DLL, game, or VM instructions were executed.",
    ],
}
_fc_output("float-helper-cfg.json").write_text(
    json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"passed": True, "instructions": len(decoded),
                  "fixed_data_refs": len(fixed_data), "indexed_data_refs": len(indexed_data),
                  "table_sha256": result["pinned_table_interval"]["sha256"],
                  "original_code_executed": False}))
