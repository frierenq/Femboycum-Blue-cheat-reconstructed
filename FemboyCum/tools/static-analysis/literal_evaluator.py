"""Linear x86 literal/call lead collector for caller-supplied image bytes.

This bounded helper does not establish branch feasibility or execute target code.
The caller supplies a detailed Capstone x86-32 disassembler, image bytes, and
stored address base. No reference image is distributed with the tool.
"""

from capstone.x86_const import X86_OP_IMM, X86_OP_REG, X86_OP_MEM

def analyze(start, *, data, base, cs):
    if not base <= start < base + len(data):
        raise ValueError("start lies outside supplied image")
    regs = {'esi': ('ptr', 0)}
    mem = {}
    pointers = {}
    vectors = {}
    literals = []
    calls = []
    recent = []
    pushes = []

    def address(op):
        if op.type != X86_OP_MEM or op.mem.index:
            return None
        r = regs.get(cs.reg_name(op.mem.base))
        if r and isinstance(r, tuple) and (r[0] == 'ptr'):
            return r[1] + op.mem.disp
        return None

    def get_bytes(offset, size):
        if offset is None:
            return None
        values = [mem.get(offset + x) for x in range(size)]
        return bytes(values) if all((isinstance(x, int) for x in values)) else None

    def value(op):
        if op.type == X86_OP_IMM:
            return op.imm & 4294967295
        if op.type == X86_OP_REG:
            return regs.get(cs.reg_name(op.reg))
        if op.type == X86_OP_MEM:
            off = address(op)
            if off in pointers and op.size == 4:
                return pointers[off]
            v = get_bytes(off, op.size)
            return int.from_bytes(v, 'little') if v is not None else None

    def write(op, val):
        if op.type == X86_OP_REG:
            regs[cs.reg_name(op.reg)] = val
        elif op.type == X86_OP_MEM:
            off = address(op)
            if off is None:
                return
            for p in list(pointers):
                if p < off + op.size and p + 4 > off:
                    del pointers[p]
            if isinstance(val, tuple) and op.size == 4:
                pointers[off] = val
                for n in range(4):
                    mem.pop(off + n, None)
            else:
                for n in range(op.size):
                    if isinstance(val, int):
                        mem[off + n] = val >> n * 8 & 255
                    else:
                        mem.pop(off + n, None)

    def describe(v, depth=0):
        if isinstance(v, tuple) and v[0] == 'ptr':
            off = v[1]
            s = []
            for k in range(128):
                ch = mem.get(off + k)
                if ch == 0 and s:
                    return ''.join(s)
                if not isinstance(ch, int) or not 32 <= ch < 127:
                    break
                s.append(chr(ch))
            if off in pointers and depth < 2:
                return {'frame_offset': hex(off), 'points_to': describe(pointers[off], depth + 1)}
            first = get_bytes(off, 4)
            if first is not None:
                return {'frame_offset': hex(off), 'first_dword': hex(int.from_bytes(first, 'little'))}
            return {'frame_offset': hex(off)}
        return hex(v) if isinstance(v, int) else None
    end = None
    for ins in cs.disasm(data[start - base:start - base + 262144], start):
        end = ins.address + ins.size
        ops = ins.operands
        recent.append((hex(ins.address), ins.mnemonic, ins.op_str))
        recent = recent[-12:]
        if ins.mnemonic == 'mov' and len(ops) == 2:
            if ops[0].type == X86_OP_REG and cs.reg_name(ops[0].reg) == 'esi' and (ins.op_str == 'esi, esp'):
                regs['esi'] = ('ptr', 0)
            else:
                write(ops[0], value(ops[1]))
        elif ins.mnemonic == 'lea' and len(ops) == 2:
            off = address(ops[1])
            write(ops[0], ('ptr', off) if off is not None else None)
        elif ins.mnemonic in ('movaps', 'movups', 'movdqa', 'movdqu'):
            if ops[0].type == X86_OP_REG:
                vectors[cs.reg_name(ops[0].reg)] = get_bytes(address(ops[1]), 16)
            else:
                off = address(ops[0])
                v = vectors.get(cs.reg_name(ops[1].reg))
                if off is not None:
                    for k in range(16):
                        if v is not None:
                            mem[off + k] = v[k]
                        else:
                            mem.pop(off + k, None)
        elif ins.mnemonic in ('xorps', 'pxor'):
            dst = cs.reg_name(ops[0].reg)
            v = vectors.get(dst)
            if ops[1].type == X86_OP_REG and ops[1].reg == ops[0].reg:
                vectors[dst] = bytes(16)
            else:
                other = get_bytes(address(ops[1]), 16)
                v = bytes((a ^ b for a, b in zip(v, other))) if v is not None and other is not None else None
                vectors[dst] = v
                if v:
                    prefix = v.split(b'\x00', 1)[0]
                    if b'\x00' in v and prefix and all((32 <= c < 127 for c in prefix)):
                        literals.append({'at': hex(ins.address), 'text': prefix.decode(), 'provenance': recent.copy()})
        elif ins.mnemonic == 'push':
            pushes.append(value(ops[0]))
        elif ins.mnemonic == 'call':
            calls.append({'at': hex(ins.address), 'target': ins.op_str, 'ecx': describe(regs.get('ecx')), 'edx': describe(regs.get('edx')), 'push_arguments_in_reverse_order': [describe(v) for v in pushes[-8:]], 'recent_literals': [x['text'] for x in literals[-3:]], 'recent_instructions': recent.copy()})
            for r in ['eax', 'ecx', 'edx']:
                regs.pop(r, None)
            vectors.clear()
            pushes.clear()
        elif ins.mnemonic == 'ret':
            break
        elif ops and ops[0].type == X86_OP_REG and (ins.mnemonic not in ('cmp', 'test', 'push', 'jmp')) and (not ins.mnemonic.startswith('j')):
            regs.pop(cs.reg_name(ops[0].reg), None)
    return {'entry': hex(start), 'end_exclusive': hex(end), 'scope': 'linear candidates, manually corroborate', 'literals': literals, 'calls': calls}
