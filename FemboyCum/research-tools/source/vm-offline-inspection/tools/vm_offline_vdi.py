"""Read-only, bounded VDI-chain/GPT inventory. No mount, boot or guest code.

Header/block definitions checked against Oracle VirtualBox VDICore.h:
https://github.com/VirtualBox/virtualbox/blob/main/src/VBox/Storage/VDICore.h
This is an independently authored reader, not imported VirtualBox code.
"""
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

import hashlib
import json
import os
import struct
import tempfile
import uuid
import xml.etree.ElementTree as ET
import zlib

# Set these only when the identified VM is fully powered off. No default
# VM path is embedded in the archived reader.
VM = Path(os.environ['FC_VM_OFFLINE_VBOX']) if 'FC_VM_OFFLINE_VBOX' in os.environ else None
WORK = _fc_output_root()

def tag(element): return element.tag.rsplit('}', 1)[-1]
def u32(data, off): return struct.unpack_from('<I',data,off)[0]
def u64(data, off): return struct.unpack_from('<Q',data,off)[0]
def uid(data): return str(uuid.UUID(bytes_le=data))

class UnallocatedBaseBlock(ValueError): pass

class Image:
    def __init__(self, path, expected, parent=None):
        self.path=path.resolve()
        self.before=path.stat()
        self.file=path.open('rb')
        self.parent=parent
        header=self.file.read(512)
        assert u32(header,64)==0xbeda107f and u32(header,68)==0x10001
        assert u32(header,72)>=384
        self.kind=u32(header,76)
        assert self.kind in (1,2,4)
        self.table_offset=u32(header,340)
        self.data_offset=u32(header,344)
        self.size=u64(header,368)
        self.block_size=u32(header,376)
        self.extra=u32(header,380)
        self.blocks=u32(header,384)
        self.allocated=u32(header,388)
        self.uuid=uid(header[392:408])
        self.modify=header[408:424]
        self.linkage=header[424:440]
        self.parent_modify=header[440:456]
        assert self.uuid==expected.strip('{}')
        assert self.block_size and self.block_size&(self.block_size-1)==0
        assert self.blocks<1_000_000 and self.blocks*self.block_size>=self.size
        assert self.data_offset>=self.table_offset+self.blocks*4
        if parent:
            assert self.kind==4 and self.linkage==uuid.UUID(parent.uuid).bytes_le
            assert self.parent_modify==parent.modify
            assert self.size==parent.size and self.block_size==parent.block_size
        else:
            assert self.kind in (1,2) and self.linkage==bytes(16)
        self.file.seek(self.table_offset)
        table=self.file.read(self.blocks*4)
        assert len(table)==self.blocks*4
        self.table=struct.unpack('<'+'I'*self.blocks,table)
        assert sum(block<0xfffffffe for block in self.table)==self.allocated
        for block in self.table:
            if block<0xfffffffe:
                assert self.data_offset+(block+1)*(self.block_size+self.extra)<=self.before.st_size
        self.header_hash=hashlib.sha256(header).hexdigest()
        self.table_hash=hashlib.sha256(table).hexdigest()
        self.bytes_read=512+len(table)

    def read(self,offset,size):
        assert 0<=offset<=self.size and 0<=size<=16*1024*1024 and offset+size<=self.size
        result=bytearray()
        while size:
            block,within=divmod(offset,self.block_size)
            amount=min(size,self.block_size-within)
            physical=self.table[block]
            if physical==0xfffffffe:
                data=bytes(amount)
            elif physical==0xffffffff:
                if self.parent is None:
                    raise UnallocatedBaseBlock(f'unallocated base block {block}: no invented sector contents')
                data=self.parent.read(offset,amount)
            else:
                self.file.seek(self.data_offset+physical*(self.block_size+self.extra)+self.extra+within)
                data=self.file.read(amount)
                self.bytes_read+=amount
                assert len(data)==amount
            result.extend(data)
            offset+=amount
            size-=amount
        return bytes(result)

    def close(self):
        self.file.close()
        after=self.path.stat()
        assert self.before.st_size==after.st_size and self.before.st_mtime_ns==after.st_mtime_ns

    def record(self):
        return {'path':str(self.path),'uuid':self.uuid,'kind':self.kind,
                'virtual_bytes':self.size,'physical_bytes':self.before.st_size,
                'block_bytes':self.block_size,'allocated_blocks':self.allocated,
                'zero_blocks':self.table.count(0xfffffffe),
                'header_first512_sha256':self.header_hash,'block_table_sha256':self.table_hash,
                'physical_bytes_read':self.bytes_read,'size_mtime_unchanged':True}

def open_chain():
    if VM is None or not VM.is_absolute():
        raise RuntimeError('set FC_VM_OFFLINE_VBOX to an absolute .vbox path; use only while powered off')
    xml=ET.fromstring(VM.read_bytes())
    media={}
    parents={}
    def walk(node,parent=None):
        if tag(node)=='HardDisk':
            disk=node.attrib['uuid']
            media[disk]=node.attrib['location']
            parents[disk]=parent
            parent=disk
        for child in node: walk(child,parent)
    walk(xml)
    machine=next(n for n in xml if tag(n)=='Machine')
    hardware=next(n for n in machine if tag(n)=='Hardware')
    images=[image.attrib['uuid'] for device in hardware.iter()
            if tag(device)=='AttachedDevice' and device.attrib.get('type')=='HardDisk'
            for image in device if tag(image)=='Image']
    assert len(images)==1
    chain=[]
    current=images[0]
    while current:
        assert current not in chain
        chain.append(current)
        current=parents[current]
    opened=[]
    try:
        for ident in reversed(chain):
            location=(VM.parent/media[ident]).resolve()
            assert location.is_relative_to(VM.parent.resolve())
            opened.append(Image(location,ident,opened[-1] if opened else None))
    except BaseException:
        for image in reversed(opened): image.close()
        raise
    return opened

def gpt(disk):
    mbr=disk.read(0,512)
    assert mbr[510:512]==b'\x55\xaa' and mbr[450]==0xee
    header=disk.read(512,512)
    assert header[:8]==b'EFI PART'
    length=u32(header,12)
    assert 92<=length<=512
    expected=u32(header,16)
    check=bytearray(header[:length]);check[16:20]=bytes(4)
    assert zlib.crc32(check)==expected
    count=u32(header,80);entry_size=u32(header,84)
    assert 0<count<=1024 and 128<=entry_size<=1024
    entries=disk.read(u64(header,72)*512,count*entry_size)
    assert zlib.crc32(entries)==u32(header,88)
    result=[]
    for index in range(count):
        entry=entries[index*entry_size:(index+1)*entry_size]
        if entry[:16]==bytes(16):continue
        start,end=u64(entry,32),u64(entry,40)
        assert start<=end and (end+1)*512<=disk.size
        item={'index':index,'type_guid':uid(entry[:16]),'partition_guid':uid(entry[16:32]),
              'start_lba':start,'end_lba':end,'name':entry[56:128].decode('utf-16le').rstrip('\0')}
        try:
            boot=disk.read(start*512,512)
        except UnallocatedBaseBlock as error:
            item['boot_sector_unavailable']=str(error)
            result.append(item)
            continue
        item.update({'oem_id':boot[3:11].decode('ascii',errors='replace'),'boot_sector_sha256':hashlib.sha256(boot).hexdigest()})
        if boot[3:11]==b'NTFS    ':
            item.update({'ntfs_bytes_per_sector':struct.unpack_from('<H',boot,11)[0],
                         'ntfs_sectors_per_cluster':boot[13],'ntfs_mft_lcn':u64(boot,48),
                         'ntfs_file_record_size_code':struct.unpack_from('<b',boot,64)[0]})
        result.append(item)
    return result

if __name__=='__main__':
    WORK.mkdir(parents=True,exist_ok=True)
    opened=open_chain()
    try:
        partitions=gpt(opened[-1])
    finally:
        for image in reversed(opened):image.close()
    report={'passed':True,'scope':'bounded read-only VDI-chain/GPT metadata inventory',
            'format_reference':'https://github.com/VirtualBox/virtualbox/blob/main/src/VBox/Storage/VDICore.h',
            'images':[image.record() for image in opened],'gpt_crc_checked':True,'partitions':partitions,
            'guest_booted_by_reader':False,'guest_files_mounted':False,'original_native_executed_by_reader':False,
            'guest_contents_cleanliness_verified':False}
    (WORK/'disk-inventory.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))
