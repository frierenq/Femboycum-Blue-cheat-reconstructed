"""Small decoded-byte/abstract-domain regression checks; no original execution."""
import sys
sys.dont_write_bytecode = True
if not __debug__: raise RuntimeError("Python -O disables assertions")

from abstract_trace import Machine, Ptr, Unknown, CS, RAW, BASE, X86_OP_MEM

def ins_at(addr):
    return next(CS.disasm(RAW[addr-BASE:addr-BASE+15], addr, count=1))

# The route-breaking case: one-operand r/m8 IMUL writes AX, not DX/EDX.
m = Machine(continue_cpuid=True)
while m.pc != 0x431e7999:
    m.step()
i = ins_at(m.pc)
assert (i.mnemonic, i.operands[0].size, m.getreg('al'), m.value(i.operands[0])) == ('imul', 1, 0, 0)
old_edx = m.reg['edx']
assert old_edx == 1377893253
m.step()
assert m.getreg('ax') == 0 and m.reg['edx'] == old_edx
assert m.flags['CF'] == m.flags['OF'] == 0

# Effective-address offsets and each constituent byte wrap modulo 2^32.
m = Machine()
m.store(Ptr('S', 0x7fffffff), 4, 0x11223344)
assert m.load(Ptr('S', -0x80000000), 1) == 0x33
m.store(Ptr('S', -4), 4, 0xaabbccdd)
assert m.load(Ptr('S', 0x100000000 - 4), 4) == m.load(Ptr('S', -4), 4)

# A byte/word slice of a stored symbolic pointer is not the full pointer.
assert isinstance(m.load(Ptr('S', 8), 1), Unknown)
assert isinstance(m.load(Ptr('D', 16), 2), Unknown)
assert isinstance(m.load(Ptr('D', 16), 4), Unknown)
try:
    m.load(Ptr('D', 24), 1)
except RuntimeError as e:
    assert 'outside 24-byte descriptor' in str(e)
else:
    raise AssertionError('out-of-descriptor fixture read was accepted')

# One-bit shifts set OF; BT preserves ZF.
m = Machine(); m.pc = 0x429a0cb8; m.reg['edx'] = 0x8000
assert (ins_at(m.pc).mnemonic, ins_at(m.pc).op_str) == ('sal', 'dx, 1')
m.step()
assert m.getreg('dx') == 0 and m.flags['CF'] == m.flags['OF'] == 1
m = Machine(); m.pc = 0x4298ca0e; m.reg['edx'] = 0x8000; m.reg['ecx'] = 1
assert (ins_at(m.pc).mnemonic, ins_at(m.pc).op_str) == ('shr', 'dx, cl')
m.step()
assert m.getreg('dx') == 0x4000 and m.flags['CF'] == 0 and m.flags['OF'] == 1
m = Machine(); m.pc = 0x429a0c8f; m.reg['edx'] = 228; m.flags['ZF'] = 1
assert ins_at(m.pc).mnemonic == 'bt'
m.step()
assert m.flags['ZF'] == 1

assert m.binary('and', Unknown('input'), 0, 16) == (0, 0, 0)
print('abstract primitive contracts: pass')
