"""Read selected guest startup hive values in memory; never imports a hive into Windows."""
import sys
sys.dont_write_bytecode = True
if not __debug__: raise RuntimeError("Python -O disables assertions")

import os
from pathlib import Path
import ctypes
import hashlib
import io
import json
import sys
from vm_offline_ntfs import Ntfs, attributes, data_runs, scan
from vm_offline_vdi import WORK, open_chain, gpt, u64
sys.path.insert(0,str(Path(os.environ['FC_RESEARCH_PYTHON_LIBS'])))
from Registry import Registry
from Registry import RegistryLog

def lookup(rows,path):
    current=5
    for component in path.strip('/').split('/'):
        choices=[]
        for index,row in rows.items():
            for name in row['names']:
                if (name['parent']==current and name['parent_sequence']==rows[current]['sequence']
                        and name['name'].casefold()==component.casefold()):
                    choices.append(index)
        assert len(set(choices))==1,(path,component,choices)
        current=choices[0]
    return current

def read_file(ntfs,index):
    record=ntfs.record(index)
    streams=[a for a in attributes(record) if a['type']==0x80 and a['name']=='']
    assert len(streams)==1
    attribute=streams[0]
    if not attribute['nonresident']:return attribute['value']
    data=attribute['data']
    assert u64(data,16)==0
    logical_size=u64(data,48)
    size=u64(data,56)
    assert size<=logical_size<=128*1024*1024,(index,size,logical_size)
    runs=data_runs(attribute,ntfs.cluster)
    assert runs[0]['vcn']==0
    result=bytearray()
    for run in runs:
        assert len(result)==run['vcn']*ntfs.cluster
        remaining=min(run['clusters']*ntfs.cluster,size-len(result))
        offset=ntfs.start+run['lcn']*ntfs.cluster
        while remaining>0:
            amount=min(remaining,1024*1024)
            result.extend(ntfs.disk.read(offset,amount))
            offset+=amount;remaining-=amount
        if len(result)==size:break
    assert len(result)==size
    return bytes(result)

def values(reg,path,names=None):
    try:key=reg.open(path)
    except Registry.RegistryKeyNotFoundException:return {'key':path,'present':False,'values':[]}
    result=[]
    for value in key.values():
        if names is not None and value.name() not in names:continue
        data=value.value()
        assert not isinstance(data,bytes),'unexpected binary startup value'
        result.append({'name':value.name(),'type':value.value_type(),'value':data})
    return {'key':path,'present':True,'values':result}

class CappedMemory(io.BytesIO):
    def write(self,data):
        assert self.tell()+len(data)<=128*1024*1024
        return super().write(data)

def recover_memory(ntfs,rows,path,raw):
    primary=CappedMemory(raw)
    logs=[]
    records=[]
    for suffix in ['.LOG1','.LOG2']:
        log_path=path+suffix
        info={'path':log_path}
        try:
            index=lookup(rows,log_path)
            data=read_file(ntfs,index)
            info.update({'mft_record':index,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
            assert data[:4]==b'regf'
            primary.seek(0)
            log=RegistryLog.RegistryLog(primary,io.BytesIO(data))
            entries=list(log._regf.log_entries())
            info.update({'first_log_sequence':log.first_log_sequence(),'eligible':log.is_eligible_log(),
                         'validated_entries':len(entries)})
            for entry in entries:
                assert entry.validate_log_entry()
                for reference,page in entry.dirty_pages_with_references():
                    assert reference.offset()+reference.size()+4096<=128*1024*1024
                    assert len(page.data())==reference.size()
            if log.is_eligible_log() and entries:
                logs.append((log,info))
        except Exception as error:
            info['not_applied']=type(error).__name__+': '+str(error)
        records.append(info)
    if len(logs)==2 and logs[1][0].is_starting_log(logs[0][0]):
        logs.reverse()
    if not logs:return raw,records
    first,first_info=logs[0]
    last=first.recover_hive()
    first_info['last_applied_sequence']=last
    if len(logs)>1 and last is not None:
        second,second_info=logs[1]
        second_info['last_applied_sequence']=second.recover_hive_continue((last+1)&0xffffffff)
    return primary.getvalue(),records

if __name__=='__main__':
    ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(),0x4000)
    opened=open_chain()
    report={'scope':'bounded read-only startup hive values; not a complete autostart/security audit',
            'guest_booted':False,'hives_imported_into_host':False,'ordinary_guest_files_written':False,
            'original_native_executed':False,'guest_contents_cleanliness_verified':False,'hives':[]}
    try:
        disk=opened[-1]
        part=next(p for p in gpt(disk) if p['index']==3)
        ntfs=Ntfs(disk,part)
        _,rows=scan(ntfs)
        for path in [os.environ['FC_GUEST_NTUSER_PATH'],'/Windows/System32/config/SOFTWARE','/Windows/System32/config/SYSTEM']:
            index=lookup(rows,path)
            raw=read_file(ntfs,index)
            assert raw[:4]==b'regf'
            reg=Registry.Registry(io.BytesIO(raw))
            assert reg._regf.hbins_size()+4096<=len(raw)
            record={'path':path,'mft_record':index,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                    'initialized_data_only':True,'all_declared_hbin_bytes_present':True,
                    'header_checksum_valid':reg._regf.validate_checksum(),
                    'sequence_numbers_match':reg._regf.validate_sequence_numbers(),
                    'sequence_numbers':[reg._regf.hive_sequence1(),reg._regf.hive_sequence2()],
                    'startup_values':[]}
            if record['header_checksum_valid'] and not record['sequence_numbers_match']:
                recovered,logs=recover_memory(ntfs,rows,path,raw)
                record['transaction_logs']=logs
                if recovered!=raw:
                    reg=Registry.Registry(io.BytesIO(recovered))
                    assert reg._regf.hbins_size()+4096<=len(recovered)
                    record['recovered_copy_in_memory']={
                        'bytes':len(recovered),'sha256':hashlib.sha256(recovered).hexdigest(),
                        'header_checksum_valid':reg._regf.validate_checksum(),
                        'sequence_numbers_match':reg._regf.validate_sequence_numbers(),
                        'sequence_numbers':[reg._regf.hive_sequence1(),reg._regf.hive_sequence2()]}
            current=record.get('recovered_copy_in_memory',record)
            if not current['header_checksum_valid'] or not current['sequence_numbers_match']:
                record['queries_skipped']='Hive recovery required; no autostart absence conclusion from unreplayed data'
                report['hives'].append(record)
                continue
            if path.endswith('NTUSER.DAT') or path.endswith('SOFTWARE'):
                for prefix in ['Microsoft\\Windows\\CurrentVersion','Wow6432Node\\Microsoft\\Windows\\CurrentVersion']:
                    for suffix in ['Run','RunOnce','Policies\\Explorer\\Run']:
                        record['startup_values'].append(values(reg,prefix+'\\'+suffix))
                if path.endswith('SOFTWARE'):
                    record['startup_values'].append(values(reg,'Microsoft\\Windows NT\\CurrentVersion\\Winlogon',{'Shell','Userinit','AutoAdminLogon'}))
                    record['startup_values'].append(values(reg,'Microsoft\\Windows NT\\CurrentVersion\\Windows',{'AppInit_DLLs','LoadAppInit_DLLs'}))
                    record['startup_values'].append(values(reg,'Microsoft\\Windows NT\\CurrentVersion',{'ProductName','CurrentBuildNumber','DisplayVersion'}))
            else:
                selected=reg.open('Select').value('Current').value()
                assert isinstance(selected,int) and 1<=selected<=99
                record['current_control_set']=selected
                base=f'ControlSet{selected:03d}'
                record['startup_values'].append(values(reg,base+'\\Control\\Session Manager',{'BootExecute'}))
                services=[]
                for key in reg.open(base+'\\Services').subkeys():
                    try:start=key.value('Start').value()
                    except Registry.RegistryValueNotFoundException:continue
                    if start not in (0,1,2):continue
                    item={'name':key.name(),'start':start}
                    for field in ['ImagePath','Type','ObjectName']:
                        try:item[field]=key.value(field).value()
                        except Registry.RegistryValueNotFoundException:pass
                    services.append(item)
                assert len(services)<1000
                record['boot_system_auto_services']=services
            report['hives'].append(record)
    finally:
        for image in reversed(opened):image.close()
    report['passed']=True
    report['all_original_hive_headers_consistent']=all(h['header_checksum_valid'] and h['sequence_numbers_match'] for h in report['hives'])
    report['all_queried_hive_copies_consistent']=all(h.get('recovered_copy_in_memory',h)['header_checksum_valid'] and h.get('recovered_copy_in_memory',h)['sequence_numbers_match'] for h in report['hives'])
    (WORK/'startup-hives.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({**report,'hives':[{k:v for k,v in h.items() if k!='boot_system_auto_services'} for h in report['hives']]},indent=2))
