# -*- coding: utf-8 -*-
# 【中文注释】用途：将VMX、SMBIOS UUID、MAC及平台状态对应起来，防止控制了错误虚拟机。
# 【中文注释】阅读副本：原版与原SHA保留；依赖源码哈希/AST抽取的驱动应执行验证过的原版。
# 【中文注释】顺序：先看常量/配置 → 关键函数 → 顶层或main入口 → 异常与清理。
# 【中文注释】历史版本能力按函数体/所属阶段判定，不能把新增守卫倒写到旧版。
# 发布版保留assert身份/准入守卫，拒绝-O/-OO以免移除这些条件。
if not __debug__:
    raise RuntimeError('Optimized Python disables safety guards; refused')
from pathlib import Path
import uuid,re,hashlib,json,subprocess,datetime,sys,os
VMRUN=Path(r'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe')
folder=Path(os.environ['STORAGE_LOCAL_EVIDENCE_DIR'])
BASE=Path(os.environ['STORAGE_VM_ROOT'])
# 【中文注释】函数 parse_running：解析平台运行清单；清单缺失目标不能直接证明它已断电。
def parse_running(raw):
 lines=[x.strip() for x in raw.splitlines() if x.strip()]
 assert lines and re.fullmatch(r'Total running VMs: [0-9]+',lines[0])
 paths=lines[1:];assert len(paths)==int(lines[0].rsplit(' ',1)[1]) and len(set(x.casefold() for x in paths))==len(paths)
 assert all(Path(x).is_absolute() and x.lower().endswith('.vmx') for x in paths)
 return {str(Path(x).resolve()).casefold() for x in paths}
# 【中文注释】函数 running：调用平台取得实际运行VM清单，不用缓存代替现场查询。
def running():
 # 【中文注释】启动具体命令/子进程；权限、目标和超时见参数，成功还要核对后置证据。
 p=subprocess.run([str(VMRUN),'-T','ws','list'],capture_output=True,timeout=20)
 assert p.returncode==0,'VMware inventory failed; never infer poweredOff from an error'
 return parse_running(p.stdout.decode('utf-8','strict'))
# 【中文注释】函数 vm_identity：读取固定VMX并转换UUID字节序，核对VM路径和MAC，拒绝未登记目标。
def vm_identity(name):
 assert name in ('stor-svc-01','stor-svc-02','client-linux-01','backup-01','monitor-01')
 path=BASE/name/(name+'.vmx');assert path.resolve()==path and path.is_file()
 wanted=('displayName','uuid.bios','ethernet0.generatedAddress','ethernet0.connectionType')
 raw_file=path.read_bytes();match=re.search(rb'^\.encoding\s*=\s*"([A-Za-z0-9_-]+)"',raw_file,re.M)
 assert match,'VMX encoding declaration absent'
 encoding=match[1].decode('ascii');assert encoding.lower() in ('gbk','cp936','utf-8','windows-1252')
 content=raw_file.decode(encoding)
 power={k:v for k,v in re.findall(r'^([A-Za-z0-9.]+)\s*=\s*"([^"\r\n]*)"\s*$',content,re.M) if k in ('cleanShutdown','softPowerOff','checkpoint.vmState')}
 data={k:v for k,v in re.findall(r'^([A-Za-z0-9.]+)\s*=\s*"([^"\r\n]*)"\s*$',content,re.M) if k in wanted}
 assert data['displayName']==name and data['ethernet0.connectionType']=='nat'
 raw=bytes.fromhex(data['uuid.bios'].replace('-',' '));assert len(raw)==16
 return {'path':str(path),'bios_uuid':str(uuid.UUID(bytes_le=raw)).upper(),'mac':data['ethernet0.generatedAddress'].lower(),
         'vmx_sha256':hashlib.sha256(raw_file).hexdigest(),'encoding':encoding,'identity_fields':data,'power_metadata':power}
# 【中文注释】函数 self_check：执行源码规定的自检路径；假后端/隔离样本不能当作真实现场故障通过。
def self_check():
 assert str(uuid.UUID(bytes_le=bytes.fromhex('00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff'))).upper()=='33221100-5544-7766-8899-AABBCCDDEEFF'
 for value in ('','Total running VMs: 2\nC:\\a.vmx\n','Total running VMs: 2\nC:\\a.vmx\nC:\\a.vmx\n','Total running VMs: 1\nrelative.vmx\n','Error: cannot connect'):
  try:parse_running(value)
  # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
  except AssertionError:pass
  else:raise AssertionError('Bad native inventory accepted')
 assert parse_running('Total running VMs: 0\n')==set()
 print('VMWARE_IDENTITY_SELF_CHECK=pass')
# 【中文注释】脚本执行入口；只有本分支受main判断保护，前面的顶层语句仍可能在导入时执行。
if __name__=='__main__':
 if sys.argv[1:]==['--self-check']:self_check()
 else:raise SystemExit('Identity library only; configure private roots, use broker mapping checks')
