"""Bounded Capstone display of read-only supplied wrapper .text windows."""
import sys
sys.dont_write_bytecode = True
if not __debug__: raise RuntimeError("Python -O disables assertions")

import os
from pathlib import Path
import hashlib
import sys
TH=Path(os.environ["FC_RESEARCH_ROOT"])
sys.path.insert(0,str(Path(os.environ["FC_RESEARCH_PYTHON_LIBS"])))
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
path=Path(os.environ["FC_RESEARCH_WRAPPER_PE"])
raw=path.read_bytes()
assert hashlib.sha256(raw).hexdigest()=='ddb620e3dc789ea51c09fedb57df738e381132c6770679b95be20fca2dcf8431'
cs=Cs(CS_ARCH_X86,CS_MODE_32);cs.detail=True
def view(start,end):
    print('window',hex(start),hex(end))
    # .text virtual start 0x10001000 maps to raw offset 0x400.
    off=start-0x10001000+0x400
    data=raw[off:off+end-start]
    for ins in cs.disasm(data,start):
        print(f'{ins.address:08x} {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}')
for lo,hi in ((0x10001380,0x10001420),(0x10002e50,0x10002f80),
              (0x10006b80,0x10006d20),(0x10006d70,0x10006e30),(0x10007140,0x10007230),
              (0x100073a0,0x100073e0),(0x100077a0,0x10007850)):
    view(lo,hi)
