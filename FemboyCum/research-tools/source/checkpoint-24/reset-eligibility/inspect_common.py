"""Bounded static prefixes of common dispatcher callbacks; lead index only."""
import sys
sys.dont_write_bytecode = True
if not __debug__: raise RuntimeError("Python -O disables assertions")

import os
from pathlib import Path
import hashlib, sys
raw=Path(os.environ["FC_RESEARCH_CORE"]).read_bytes()
assert hashlib.sha256(raw).hexdigest()=='682ce73b371349f87da6fd9365f8550e240dcdb97951e80445e70286275ad96e'
sys.path.insert(0,os.environ["FC_RESEARCH_PYTHON_LIBS"])
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
cs=Cs(CS_ARCH_X86,CS_MODE_32);base=0x412a0000
for start in (0x41503940,0x414fcfc0,0x415728f0,0x4151a440,0x41407940,0x41418e00):
    print(f'FUNCTION PREFIX {start:08x}')
    ins=list(cs.disasm(raw[start-base:start-base+0x200],start))
    for i in ins:
        print(f'{i.address:08x} {i.bytes.hex():20} {i.mnemonic} {i.op_str}')
        if i.mnemonic.startswith('ret'):break
