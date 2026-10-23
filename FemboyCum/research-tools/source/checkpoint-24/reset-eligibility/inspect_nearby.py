"""Static nearby disassembly for reset-call investigation."""
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
for start,end in [(0x415de900,0x415debd0),(0x415df1e4,0x415df400)]:
    print(f'REGION {start:08x}..{end:08x}')
    for i in cs.disasm(raw[start-base:end-base],start):
        print(f'{i.address:08x} {i.bytes.hex():20} {i.mnemonic} {i.op_str}')
