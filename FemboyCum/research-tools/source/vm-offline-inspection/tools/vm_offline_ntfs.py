"""Bounded NTFS MFT metadata inventory over read-only VDI streams.

No guest files are opened by the OS, mounted, extracted or executed.
Layout references:
https://learn.microsoft.com/en-us/windows/win32/devnotes/attribute-record-header
https://learn.microsoft.com/en-us/windows/win32/devnotes/file-record-segment-header
https://github.com/torvalds/linux/blob/master/fs/ntfs3/ntfs.h
"""
import sys
sys.dont_write_bytecode = True
if not __debug__: raise RuntimeError("Python -O disables assertions")

import ctypes
import hashlib
import json
import struct
from vm_offline_vdi import WORK, open_chain, gpt, u32, u64

def u16(data,off): return struct.unpack_from('<H',data,off)[0]

def fixed_record(data,sector=512):
    assert data[:4]==b'FILE'
    off,count=u16(data,4),u16(data,6)
    assert count==len(data)//sector+1 and 8<=off and off+count*2<sector-2
    sequence=data[off:off+2]
    result=bytearray(data)
    for index in range(1,count):
        tail=index*sector-2
        assert data[tail:tail+2]==sequence
        result[tail:tail+2]=data[off+index*2:off+index*2+2]
    assert u32(result,28)==len(data) and u32(result,24)<=len(data)
    return bytes(result)

def attributes(record):
    offset=u16(record,20)
    used=u32(record,24)
    while offset+4<=used:
        kind=u32(record,offset)
        if kind==0xffffffff:return
        assert offset+16<=used
        length=u32(record,offset+4)
        assert length>=24 and length%8==0 and offset+length<=used
        data=record[offset:offset+length]
        nonresident=data[8]
        assert nonresident in (0,1)
        name_length=data[9]
        name_offset=u16(data,10)
        if name_length:
            assert name_offset+name_length*2<=length
            name=data[name_offset:name_offset+name_length*2].decode('utf-16le')
        else:name=''
        if nonresident:
            assert length>=64
            value=None
        else:
            value_length=u32(data,16);value_offset=u16(data,20)
            assert value_offset+value_length<=length
            value=data[value_offset:value_offset+value_length]
        yield {'type':kind,'name':name,'nonresident':nonresident,'data':data,'value':value}
        offset+=length
    raise ValueError('unterminated attribute records')

def data_runs(attribute,cluster):
    data=attribute['data']
    assert attribute['nonresident'] and u16(data,12)==0
    current_vcn=u64(data,16)
    highest=u64(data,24)
    offset=u16(data,32)
    lcn=0
    result=[]
    while offset<len(data):
        header=data[offset];offset+=1
        if header==0:break
        nlen,noff=header&15,header>>4
        assert 1<=nlen<=8 and 1<=noff<=8 and offset+nlen+noff<=len(data)
        count=int.from_bytes(data[offset:offset+nlen],'little')
        assert count>0
        offset+=nlen
        lcn+=int.from_bytes(data[offset:offset+noff],'little',signed=True)
        offset+=noff
        assert lcn>=0
        result.append({'vcn':current_vcn,'lcn':lcn,'clusters':count})
        current_vcn+=count
    else:raise ValueError('unterminated mapping pairs')
    assert current_vcn==highest+1
    return result

class Ntfs:
    def __init__(self,disk,partition):
        self.disk=disk
        self.start=partition['start_lba']*512
        self.sector=partition['ntfs_bytes_per_sector']
        self.cluster=self.sector*partition['ntfs_sectors_per_cluster']
        code=partition['ntfs_file_record_size_code']
        self.record_size=(1<<(-code)) if code<0 else code*self.cluster
        assert self.sector==512 and self.cluster==4096 and self.record_size==1024
        record=fixed_record(disk.read(self.start+partition['ntfs_mft_lcn']*self.cluster,self.record_size))
        attrs=list(attributes(record))
        streams=[a for a in attrs if a['type']==0x80 and a['name']=='']
        assert len(streams)==1
        self.runs=data_runs(streams[0],self.cluster)
        data=streams[0]['data']
        assert u64(data,16)==0
        self.data_size=u64(data,48)
        self.valid_size=u64(data,56)
        assert self.data_size<=self.runs[-1]['vcn']*self.cluster+self.runs[-1]['clusters']*self.cluster
        assert self.valid_size<=self.data_size<=256*1024*1024
        assert self.valid_size%self.record_size==0
        # Require every byte of the requested MFT range to be mapped explicitly.
        position=0
        for run in self.runs:
            assert run['vcn']*self.cluster==position
            position+=run['clusters']*self.cluster
        assert position>=self.data_size
        self.bootstrap_hash=hashlib.sha256(record).hexdigest()
        volume=list(attributes(self.record(3)))
        info=next(a['value'] for a in volume if a['type']==0x70)
        assert info is not None and len(info)>=12
        self.version=(info[8],info[9])
        self.volume_flags=u16(info,10)
        assert self.version in ((3,0),(3,1))

    def record(self,index):
        position=index*self.record_size
        for run in self.runs:
            start=run['vcn']*self.cluster
            end=start+run['clusters']*self.cluster
            if start<=position and position+self.record_size<=end:
                return fixed_record(self.disk.read(self.start+run['lcn']*self.cluster+position-start,self.record_size))
        raise ValueError('record outside mapped MFT extent')

    def read_mft(self):
        result=bytearray()
        for run in self.runs:
            remaining=min(run['clusters']*self.cluster,self.valid_size-len(result))
            offset=self.start+run['lcn']*self.cluster
            while remaining>0:
                amount=min(remaining,1024*1024)
                result.extend(self.disk.read(offset,amount))
                offset+=amount;remaining-=amount
            if len(result)==self.valid_size:break
        assert len(result)==self.valid_size
        return bytes(result)

def scan(ntfs):
    raw=ntfs.read_mft()
    rows={}
    names=[]
    empty=0
    for index in range(len(raw)//ntfs.record_size):
        data=raw[index*ntfs.record_size:(index+1)*ntfs.record_size]
        if data[:4]!=b'FILE':
            assert data==bytes(ntfs.record_size)
            empty+=1
            continue
        record=fixed_record(data,ntfs.sector)
        flags=u16(record,22)
        if not flags&1:continue
        row={'record':index,'sequence':u16(record,16),'directory':bool(flags&2),'names':[]}
        base=u64(record,32)&0xffffffffffff
        if base:row['base_record']=base
        for attribute in attributes(record):
            if attribute['type']!=0x30:continue
            value=attribute['value']
            assert value is not None and len(value)>=66
            length=value[64];name_type=value[65]
            assert name_type<=3 and 66+length*2<=len(value)
            name=value[66:66+length*2].decode('utf-16le')
            parent=u64(value,0)
            item={'name':name,'type':name_type,'parent':parent&0xffffffffffff,
                  'parent_sequence':parent>>48,'size_from_name':u64(value,48)}
            row['names'].append(item)
            if name_type!=2:names.append((index,item))
        rows[index]=row
    assert 5 in rows and rows[5]['directory']
    cache={5:'/'}
    def path_for(index,seen=()):
        if index in cache:return cache[index]
        if index in seen or len(seen)>128 or index not in rows:return None
        row=rows[index]
        choices=sorted(row['names'],key=lambda n:n['type']==2)
        for item in choices:
            parent=rows.get(item['parent'])
            if parent is None or parent['sequence']!=item['parent_sequence']:continue
            parent_path=path_for(item['parent'],seen+(index,))
            if parent_path:
                result=parent_path.rstrip('/')+'/'+item['name']
                cache[index]=result
                return result
        return None
    selected=[]
    samples=[]
    unresolved=0
    resolved=0
    for index,item in names:
        if item['type']==2:continue
        parent=rows.get(item['parent'])
        valid_parent=parent is not None and parent['sequence']==item['parent_sequence']
        parent_path=path_for(item['parent']) if valid_parent else None
        path=parent_path.rstrip('/')+'/'+item['name'] if parent_path is not None else None
        if path:resolved+=1
        else:unresolved+=1
        info={'path':path,'record':index,'directory':rows[index]['directory'],
              'name':item['name'],'size_from_name':item['size_from_name']}
        if any(term in item['name'].lower() for term in os.environ.get('FC_NTFS_SAMPLE_TERMS', '').lower().split(',') if term):
            samples.append(info)
        if path:
            lower=path.lower()
            if lower.startswith('/users/') or lower.endswith('/startup') or '/startup/' in lower:
                selected.append(info)
    return {'mft_valid_bytes':len(raw),'record_slots':len(raw)//ntfs.record_size,
            'active_records':len(rows),'empty_slots':empty,'filename_attributes':len(names),
            'resolved_filename_attributes':resolved,'unresolved_filename_parent_links':unresolved,
            'ntfs_version':list(ntfs.version),'volume_flags':ntfs.volume_flags,
            'mft_sha256':hashlib.sha256(raw).hexdigest(),'mapped_runs':ntfs.runs,
            'root_and_parent_sequence_checked':True,'selected_user_and_startup_metadata':selected,
            'sample_name_matches':samples},rows

if __name__=='__main__':
    WORK.mkdir(parents=True,exist_ok=True)
    ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
    opened=open_chain()
    try:
        disk=opened[-1]
        partitions=gpt(disk)
        main=next(p for p in partitions if p['index']==3 and p.get('oem_id')=='NTFS    ')
        ntfs=Ntfs(disk,main)
        result,rows=scan(ntfs)
    finally:
        for image in reversed(opened):image.close()
    report={'passed':True,'scope':'bounded main-volume MFT filename metadata, not a guest cleanliness attestation',
            'guest_booted_by_reader':False,'mounted':False,'guest_file_contents_extracted':False,
            'original_native_executed_by_reader':False,'guest_contents_cleanliness_verified':False,**result}
    (WORK/'ntfs-metadata.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({key:value for key,value in report.items() if key!='selected_user_and_startup_metadata'},indent=2))
    print('Selected metadata rows:',len(report['selected_user_and_startup_metadata']))
