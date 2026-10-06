#!/usr/bin/python
# -*- coding: utf-8 -*-
# 【中文注释】用途：普通文件LUN备份运行/历史版本；各before版本的能力和已知缺口见所属步骤。
# 【中文注释】阅读副本：原版与原SHA保留；依赖源码哈希/AST抽取的驱动应执行验证过的原版。
# 【中文注释】顺序：先看常量/配置 → 关键函数 → 顶层或main入口 → 异常与清理。
# 【中文注释】历史版本能力按函数体/所属阶段判定，不能把新增守卫倒写到旧版。
from __future__ import print_function
# 发布版保留assert身份/准入守卫，拒绝-O/-OO以免移除这些条件。
if not __debug__:
    raise RuntimeError('Optimized Python disables safety guards; refused')
import os,sys,json,stat,hashlib,subprocess,tarfile,posixpath,time,shutil,tempfile,re
try:TEXT=unicode;INTEGER=(int,long)
# 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
except NameError:TEXT=str;INTEGER=(int,)
STAGING_LIMIT=24*1024**3
STAGING_COUNT_LIMIT=8
SPACE_HEADROOM=512*1024**2
INODE_HEADROOM=16

# 【中文注释】函数 text：将字节解码为文本，保持Python2/3下中文路径的表示一致。
def text(value):
 return value.decode('utf-8') if isinstance(value,bytes) and not isinstance(value,TEXT) else value
# 【中文注释】函数 wire：按当前Python版本准备本地系统调用参数；Python2场景需要UTF-8字节。
def wire(value):return value.encode('utf-8') if sys.version_info[0]==2 and isinstance(value,TEXT) else value
# 【中文注释】函数 canon：把对象按固定字段顺序序列化，得到稳定的摘要输入。
def canon(value):return json.dumps(value,sort_keys=True,ensure_ascii=True).encode('ascii')
# 【中文注释】函数 digest：读取文件内容计算摘要；实际算法、读取边界和常规文件守卫以该版本函数体为准。
def digest(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  # 【中文注释】身份/路径/权限守卫：只允许本轮授权对象，阻止链接、替换或跨目录操作。
  assert stat.S_ISREG(os.fstat(fd).st_mode)
  h=hashlib.sha256()
  with os.fdopen(fd,'rb') as f:
   fd=None
   while True:
    block=f.read(1048576)
    if not block:break
    h.update(block)
  return h.hexdigest()
 # 【中文注释】无论成功或失败都处理本轮清理/释放；仍须遵守内部的目标与未决状态守卫。
 finally:
  if fd is not None:os.close(fd)
# 【中文注释】函数 load：读取JSON状态或配置；该版本如何处理缺失、损坏、大小上限见异常分支。
def load(path,maximum=32*1024*1024):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as f:
  # 【中文注释】身份/路径/权限守卫：只允许本轮授权对象，阻止链接、替换或跨目录操作。
  assert stat.S_ISREG(os.fstat(f.fileno()).st_mode) and os.fstat(f.fileno()).st_size<=maximum
  return json.load(f)
# 【中文注释】函数 atomic：先写同目录暂存文件并刷盘，再用重命名发布，避免读到半份状态。
def atomic(path,value,mode=0o600):
 parent=os.path.dirname(path);fd,tmp=tempfile.mkstemp(prefix='.lun-stage-',dir=parent)
 try:
  # 【中文注释】刷盘该文件/状态，减少进程中断时只留下内存成功的风险。
  os.fchmod(fd,mode);os.write(fd,canon(value)+b'\n');os.fsync(fd);os.close(fd);fd=None;os.rename(tmp,path)
 # 【中文注释】无论成功或失败都处理本轮清理/释放；仍须遵守内部的目标与未决状态守卫。
 finally:
  if fd is not None:os.close(fd)
  # 【中文注释】删除或清理此对象；必须先满足上方的所有权、真实路径或本轮标识检查。
  if os.path.exists(tmp):os.unlink(tmp)
# 【中文注释】函数 run：封装本地/原生命令及退出码；是否有副作用取决于传入命令，不默认只读。
def run(args,limit=900):
 # Keep the job lock in native children so a killed parent cannot trigger cleanup
 # while its tar/rsync process is still writing.
 # 【中文注释】启动具体命令/子进程；权限、目标和超时见参数，成功还要核对后置证据。
 p=subprocess.Popen(['/usr/bin/timeout','-k','5',str(limit)]+[wire(x) for x in args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=False)
 a,b=p.communicate()
 if p.returncode:raise RuntimeError('Native '+os.path.basename(args[0])+' failed with exit '+str(p.returncode)+'; output withheld')
 return a
# 【中文注释】函数 protected：验证私有目录的真实路径、root属主和权限；不能借符号链接扩大操作范围。
def protected(path):
 s=os.lstat(path);assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700 and os.path.realpath(path)==path
# 【中文注释】函数 remove_owned：先核对真实父路径与root属主，再移除自有目录，拒绝跨目录清理。
def remove_owned(path,parent):
 path=wire(path);parent=wire(parent)
 # 【中文注释】身份/路径/权限守卫：只允许本轮授权对象，阻止链接、替换或跨目录操作。
 assert os.path.dirname(os.path.realpath(path))==parent and os.path.realpath(path)==path and os.stat(path).st_uid==0
 # 【中文注释】删除或清理此对象；必须先满足上方的所有权、真实路径或本轮标识检查。
 shutil.rmtree(path)

# 【中文注释】函数 stage_info：检查暂存目录、挂载边界、对象类型及指纹，并统计实际/逻辑空间。
def stage_info(parent,name,scope):
 parent=wire(parent);path=parent+'/'+wire(name);protected(path)
 mounts=[wire(text(x)) for x in run(['findmnt','-rn','-o','TARGET'],20).splitlines()]
 assert not any(m==path or m.startswith(path+'/') for m in mounts),'Refuse mounted staging paths'
 root=os.lstat(path);rows=[];seen=set();allocated=logical=0
 # 【中文注释】函数 failed：把遍历等底层错误继续抛出，避免对象缺失却返回不完整的成功视图。
 def failed(error):raise error
 for current,dirs,files in os.walk(path,followlinks=False,onerror=failed):
  # 【中文注释】身份/路径/权限守卫：只允许本轮授权对象，阻止链接、替换或跨目录操作。
  assert os.path.realpath(current)==current and not os.path.ismount(current)
  for target in [current]+[os.path.join(current,n) for n in files]+[os.path.join(current,n) for n in dirs if os.path.islink(os.path.join(current,n))]:
   s=os.lstat(target);assert s.st_dev==root.st_dev
   # 【中文注释】身份/路径/权限守卫：只允许本轮授权对象，阻止链接、替换或跨目录操作。
   assert stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode) or stat.S_ISLNK(s.st_mode)
   rows.append([text(os.path.relpath(target,path)),s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_blocks,s.st_mtime,s.st_ctime])
   key=(s.st_dev,s.st_ino)
   if key not in seen:allocated+=s.st_blocks*512;seen.add(key)
   if stat.S_ISREG(s.st_mode):logical+=s.st_size
   assert len(rows)<=100000,'Staging inventory object limit exceeded'
 # ponytail: metadata fingerprint and root-only task lock; hostile root writers require filesystem isolation.
 return {'scope':scope,'name':text(name),'path':text(path),'allocated_bytes':allocated,'logical_bytes':logical,
         'objects':len(rows),'directory_mtime':root.st_mtime,'fingerprint':hashlib.sha256(canon(sorted(rows))).hexdigest()}

# 【中文注释】函数 staging_report：汇总可识别暂存及不安全项，用于准入和定向清理判断。
def staging_report(config):
 paths=[('work',config['work'],r'^stage-[1-9][0-9]{0,15}$')]
 if config['role']=='publish':paths.append(('history',config['history'],r'^\.(?:stage-[1-9][0-9]{0,15}|interrupted-[1-9][0-9]{0,15}-[1-9][0-9]{0,19})$'))
 items=[];unsafe=[]
 for scope,parent,pattern in paths:
  protected(wire(parent))
  for name in sorted(os.listdir(wire(parent))):
   if not re.match(pattern,text(name)):continue
   try:items.append(stage_info(parent,name,scope))
   # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
   except Exception as error:unsafe.append({'scope':scope,'name':text(name),'error_type':type(error).__name__})
 allocated=sum(x['allocated_bytes'] for x in items)
 return {'items':items,'unsafe':unsafe,'directories':len(items)+len(unsafe),'allocated_bytes':allocated,
         'logical_bytes':sum(x['logical_bytes'] for x in items),'limit_bytes':STAGING_LIMIT,'limit_directories':STAGING_COUNT_LIMIT,
         'new_job_blocked':bool(unsafe or len(items)>=STAGING_COUNT_LIMIT or allocated>=STAGING_LIMIT),
         'oldest_directory_mtime':min([x['directory_mtime'] for x in items]+[time.time()]),'checked_timestamp':int(time.time())}

# 【中文注释】函数 require_staging_capacity：核对目录数、预估预算和可用空间；这是准入估算，不是整个卷的硬配额。
def require_staging_capacity(config,reserve_bytes,reserve_objects=0):
 assert type(reserve_bytes) in INTEGER and reserve_bytes>=0
 assert type(reserve_objects) in INTEGER and 0<=reserve_objects<=20032
 report=staging_report(config)
 assert not report['unsafe'] and report['directories']<STAGING_COUNT_LIMIT,'Staging directory limit/unsafe entry; old versions retained'
 assert report['allocated_bytes']+reserve_bytes<=STAGING_LIMIT,'Staging admission budget exceeded; old versions retained'
 free=os.statvfs(wire(config['work'] if config['role']=='upload' else config['history']))
 assert free.f_bavail*free.f_frsize>reserve_bytes+SPACE_HEADROOM,'Staging free-space guard; old versions retained'
 assert free.f_favail>reserve_objects+INODE_HEADROOM,'Staging free-inode guard; old versions retained'

# 【中文注释】函数 discard_staging：根据刚读取的单目标指纹重新验证后删除；只准清理指定自有暂存。
def discard_staging(config,scope,name,fingerprint):
 # 【中文注释】身份/路径/权限守卫：只允许本轮授权对象，阻止链接、替换或跨目录操作。
 assert scope in ('work','history') and re.match(r'^[0-9a-f]{64}$',fingerprint)
 report=staging_report(config);assert not report['unsafe'],'Refuse cleanup with unsafe staging entries'
 matches=[x for x in report['items'] if x['scope']==scope and x['name']==name]
 # 【中文注释】身份/路径/权限守卫：只允许本轮授权对象，阻止链接、替换或跨目录操作。
 assert len(matches)==1 and matches[0]['fingerprint']==fingerprint,'Staging missing/changed; read a fresh report'
 parent=config['work'] if scope=='work' else config['history']
 # 【中文注释】身份/路径/权限守卫：只允许本轮授权对象，阻止链接、替换或跨目录操作。
 assert stage_info(parent,name,scope)['fingerprint']==fingerprint
 remove_owned(parent+'/'+wire(name),parent)
 return {'status':'discarded_staging','removed':matches[0],'remaining':staging_report(config)}
# 【中文注释】函数 safe_name：规范相对归档路径，拒绝绝对路径和父目录穿越。
def safe_name(name):
 name=posixpath.normpath(text(name))
 assert not name.startswith('/') and name!='..' and not name.startswith('../')
 return name
# 【中文注释】函数 archive_name：取得归档成员逻辑名称，兼容GNU sparse的PAX名称字段。
def archive_name(member):
 return safe_name(member.pax_headers.get('GNU.sparse.name',member.name))
# 【中文注释】函数 archive_size：取得稀疏成员的逻辑大小；压缩/稀疏占用不能替代恢复容量判断。
def archive_size(member):
 value=member.pax_headers.get('GNU.sparse.realsize',member.pax_headers.get('GNU.sparse.size'))
 if value is None:return member.size
 assert member.isreg() and re.match(r'^[0-9]{1,16}$',value)
 value=int(value);assert value<=10*1024**3
 return value
# 【中文注释】函数 tree：采集对象树和此版本定义的内容/元数据/硬链接信息；不将目录名相同当作数据相同。
def tree(base):
 base=wire(base)
 entries={};inodes={}
 for current,dirs,files in os.walk(base,followlinks=False):
  # 【中文注释】身份/路径/权限守卫：只允许本轮授权对象，阻止链接、替换或跨目录操作。
  assert os.path.realpath(current)==current
  if current==base:dirs[:]=[n for n in dirs if not n.startswith('.codex_joint_')]
  paths=([current] if current==base else [])+[os.path.join(current,n) for n in dirs+files]
  for path in paths:
   rel=text(os.path.relpath(path,base));s=os.lstat(path)
   row={'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'mtime_seconds':int(s.st_mtime)}
   if stat.S_ISREG(s.st_mode):
    row.update({'type':'file','size':s.st_size,'sha256':digest(path),'sparse':s.st_size>1048576 and s.st_blocks*512<s.st_size//2})
    inodes.setdefault((s.st_dev,s.st_ino),[]).append(rel)
   elif stat.S_ISLNK(s.st_mode):
    target=text(os.readlink(path));assert not target.startswith('/')
    safe_name(posixpath.join(posixpath.dirname(rel),target));row.update({'type':'symlink','target':target})
   elif stat.S_ISDIR(s.st_mode):row['type']='directory'
   else:raise ValueError('Only ordinary files/directories and relative links are supported')
   if row['type'] in ('file','directory'):
    row['acl_sha256']=hashlib.sha256(run(['getfacl','-cpn',path],30)).hexdigest()
    raw=run(['getfattr','-d','-m','^user\\.','-e','hex','--absolute-names',path],30)
    raw=b'\n'.join(sorted(x for x in raw.splitlines() if x and not x.startswith(b'#')))
    row['user_xattr_sha256']=hashlib.sha256(raw).hexdigest()
   entries[rel]=row
   assert len(entries)<=20000,'Lab object limit exceeded'
 return {'entries':entries,'hardlink_groups':sorted(sorted(v) for v in inodes.values() if len(v)>1)}

# 【中文注释】函数 validate_archive：核对归档成员、链接、路径/大小/身份与清单，防止解包越界或对象替换。
def validate_archive(path,manifest):
 assert os.path.getsize(path)<=10*1024**3
 members={};links=set()
 with tarfile.open(path,'r:',encoding='utf-8') as tar:
  for m in tar:
   name=archive_name(m);assert name not in members
   assert m.isdir() or m.isreg() or m.issym() or m.islnk()
   if m.issym():
    assert not text(m.linkname).startswith('/')
    safe_name(posixpath.join(posixpath.dirname(name),text(m.linkname)));links.add(name)
   if m.islnk():safe_name(m.linkname)
   members[name]=m;assert len(members)<=20000
 assert set(members)==set(manifest['tree']['entries']),'Archive member paths differ from source manifest'
 for name,m in members.items():
  parts=name.split('/')
  assert all('/'.join(parts[:i]) not in links for i in range(1,len(parts)))
  row=manifest['tree']['entries'][name]
  assert (row['type']=='directory' and m.isdir()) or (row['type']=='symlink' and m.issym()) or (row['type']=='file' and (m.isreg() or m.islnk()))
  if m.isreg():assert archive_size(m)==row['size'],'Archive logical file size differs'
  assert m.uid==row['uid'] and m.gid==row['gid'] and m.mode==row['mode'] and int(m.mtime)==row['mtime_seconds'],'Archive header identity/mode/mtime differs'
 logical=sum(archive_size(m) for m in members.values() if m.isreg())
 assert logical<=10*1024**3,'Lab restore logical size exceeded'
 return logical
# 【中文注释】函数 restore_verified：在新隔离目录解包并比较对象树；归档摘要匹配不能代替真实恢复验真。
def restore_verified(archive,manifest,destination):
 # 【中文注释】存在性守卫：拒绝覆盖旧结果/已有对象，或拒绝依赖缺失；看条件正负方向。
 assert not os.path.exists(destination);os.mkdir(destination,0o700)
 validate_archive(archive,manifest)
 run(['tar','--acls','--xattrs','--xattrs-include=user.*','--sparse','--numeric-owner','--same-owner','-xpf',archive,'-C',destination])
 assert tree(destination)==manifest['tree'],'Restored content/metadata differs from source'
# 【中文注释】函数 bundle：验证ready、归档与manifest摘要及来源身份，只有完整包才能继续发布。
def bundle(path):
 ready=load(path+'/ready.json',65536)
 assert ready.get('schema')==1 and type(ready.get('generation')) in INTEGER and 0<ready['generation']<2**53
 for key,file in [('archive_sha256','snapshot.tar'),('manifest_sha256','manifest.json')]:
  assert isinstance(ready.get(key),TEXT if sys.version_info[0]==3 else (str,unicode)) and re.match(r'^[0-9a-f]{64}$',ready[key])
  assert digest(path+'/'+file)==ready[key]
 manifest=load(path+'/manifest.json')
 assert manifest.get('schema')==1 and manifest.get('generation')==ready['generation'] and manifest.get('source')=='client-linux-01'
 assert manifest.get('source_uuid')=='{{LOCAL_LUN_UUID}}'
 # 旧schema1历史没有此字段仍可恢复；新包记录采集当时绑定，不能将其当当前会话身份证明。
 if 'source_binding' in manifest:
  binding=manifest['source_binding'];assert isinstance(binding,dict)
  assert set(binding)==set(('major_minor','device_path','sid','iqn','portal','tpgt','lun'))
  assert type(binding['sid']) in INTEGER and binding['sid']>=0 and type(binding['tpgt']) in INTEGER and 0<=binding['tpgt']<=65535 and type(binding['lun']) in INTEGER
  assert re.match(r'^[0-9]+:[0-9]+$',binding['major_minor']) and binding['device_path'].startswith('/sys/devices/')
  assert binding.get('iqn')=='iqn.2026-10.example.test:storage.lun01' and binding.get('portal')=='192.0.2.100:3260' and binding.get('lun')==0
 return ready,manifest
# 【中文注释】函数 metric：发布本轮状态及真实历史成功时间；失败不能刷新旧成功为新成功。
def metric(config,kind,status,receipt=None):
 path=config['metric'];now=int(time.time())
 lines=['lun01_'+kind+'_status '+str(status),'lun01_'+kind+'_attempt_timestamp '+str(now)]
 state_path=config['work']+'/last-'+kind+'.json'
 previous=load(state_path) if os.path.isfile(state_path) else {}
 if receipt:atomic(state_path,receipt);previous=receipt
 if previous:
  lines+=['lun01_'+kind+'_last_success_timestamp '+str(previous['verified_timestamp'] if kind=='publish' else previous['uploaded_timestamp']),
          'lun01_'+kind+'_generation '+str(previous['generation'])]
  if 'source_capture_started' in previous:lines+=['lun01_'+kind+'_data_timestamp '+str(previous['source_capture_started'])]
 if kind=='upload':
  confirmed=previous.get('verified_timestamp',0)
  lines+=['lun01_upload_verified_status '+str(int(bool(confirmed))),
          'lun01_upload_last_verified_timestamp '+str(confirmed)]
 staging=staging_report(dict(config,role=kind))
 for suffix,key in [('staging_directories','directories'),('staging_allocated_bytes','allocated_bytes'),('staging_logical_bytes','logical_bytes'),
                    ('staging_check_timestamp','checked_timestamp'),('staging_new_job_blocked','new_job_blocked')]:
  lines.append('lun01_'+kind+'_'+suffix+' '+str(int(staging[key])))
 lines.append('lun01_'+kind+'_staging_unsafe_entries '+str(len(staging['unsafe'])))
 parent=os.path.dirname(path);fd,tmp=tempfile.mkstemp(prefix='.lun01-',dir=parent)
 # 【中文注释】刷盘该文件/状态，减少进程中断时只留下内存成功的风险。
 os.fchmod(fd,0o644);os.write(fd,('\n'.join(lines)+'\n').encode('ascii'));os.fsync(fd);os.close(fd);os.rename(tmp,path)
# 【中文注释】函数 session_rows：处理此命名步骤的参数与返回值；具体边界/异常按下方函数体及所属阶段核对。
def session_rows(raw):
 """只解析实验用TCP行，IQN/portal/SID必须在同一行；不以子串匹配其他目标或拼两行。"""
 rows=[]
 for line in text(raw).splitlines():
  if not line.strip():continue
  m=re.match(r'^tcp:\s+\[([0-9]+)\]\s+(\d+\.\d+\.\d+\.\d+:[1-9][0-9]*),([0-9]+)\s+(iqn\.[^\s]+)(?:\s+\(non-flash\))?\s*$',line.strip())
  assert m,'Unsupported iSCSI session listing format'
  address,port=m.group(2).rsplit(':',1);octets=[int(x) for x in address.split('.')]
  assert all(0<=x<=255 for x in octets) and '.'.join(str(x) for x in octets)==address and 1<=int(port)<=65535 and 0<=int(m.group(3))<=65535
  rows.append({'sid':int(m.group(1)),'portal':m.group(2),'tpgt':int(m.group(3)),'iqn':m.group(4)})
 return rows

# 【中文注释】函数 bound_session：处理此命名步骤的参数与返回值；具体边界/异常按下方函数体及所属阶段核对。
def bound_session(rows,sid,iqn,portal,tpgt):
 """挂载设备所属SID只可有一个精确元组；重复/错TPGT/目标后缀均拒绝。"""
 assert type(sid) in INTEGER and sid>=0 and type(tpgt) in INTEGER and 0<=tpgt<=65535
 hits=[r for r in rows if r['sid']==sid]
 assert len(hits)==1 and hits[0]=={'sid':sid,'iqn':iqn,'portal':portal,'tpgt':tpgt},'Mounted device session tuple mismatch'
 return hits[0]

# 【中文注释】函数 iscsi_device_binding：处理此命名步骤的参数与返回值；具体边界/异常按下方函数体及所属阶段核对。
def iscsi_device_binding(source,config):
 """以实际块设备major:minor追到sysfs会话/LUN；当前只支持一个直接TCP设备，拒绝未知映射。"""
 s=os.stat(wire(source));assert stat.S_ISBLK(s.st_mode)
 number=str(os.major(s.st_rdev))+':'+str(os.minor(s.st_rdev))
 block='/sys/dev/block/'+number;device=os.path.realpath(block+'/device')
 # 【中文注释】存在性守卫：拒绝覆盖旧结果/已有对象，或拒绝依赖缺失；看条件正负方向。
 assert os.path.exists(block+'/device') and device.startswith('/sys/devices/'),'Unsupported block mapping (including dm/multipath/partition)'
 sessions=[p for p in device.split('/') if re.match(r'^session[0-9]+$',p)]
 assert len(sessions)==1
 sid=int(sessions[0][7:]);target=re.match(r'^[0-9]+:[0-9]+:[0-9]+:([0-9]+)$',os.path.basename(device));assert target
 expected_lun=config.get('lun',0);assert type(expected_lun) in INTEGER and expected_lun>=0
 lun=int(target.group(1));assert lun==expected_lun,'Unexpected target LUN number'
 session='/sys/class/iscsi_session/session'+str(sid)
 # 【中文注释】函数 attribute：处理此命名步骤的参数与返回值；具体边界/异常按下方函数体及所属阶段核对。
 def attribute(base,key):
  with open(base+'/'+key,'rb') as f:return f.read(4096).decode('ascii').strip()
 iqn=attribute(session,'targetname');tpgt=int(attribute(session,'tpgt'))
 assert iqn==config['iqn'] and attribute(session,'state')=='LOGGED_IN'
 connections=[]
 for name in os.listdir('/sys/class/iscsi_connection'):
  if re.match(r'^connection'+str(sid)+r':[0-9]+$',name):connections.append(name)
 assert len(connections)==1,'Multiple/unknown connections unsupported'
 connection='/sys/class/iscsi_connection/'+connections[0]
 persistent=attribute(connection,'persistent_address')+':'+attribute(connection,'persistent_port')
 current=attribute(connection,'address')+':'+attribute(connection,'port')
 expected=config.get('portal','192.0.2.100:3260')
 assert persistent==current==expected,'Unexpected or redirected iSCSI portal'
 rows=session_rows(run(['iscsiadm','-m','session'],20))
 bound_session(rows,sid,iqn,expected,tpgt)
 return {'major_minor':number,'device_path':device,'sid':sid,'iqn':iqn,'portal':expected,'tpgt':tpgt,'lun':lun}

# 【中文注释】函数 source_ready：核对实际挂载、UUID与iSCSI来源；此版本会话是精确匹配还是子串匹配要看函数体。
def source_ready(config):
 """精确挂载/UUID后绑定真正设备会话；返回身份供tar前后比较，避免换设备冒充相同源。"""
 raw=run(['findmnt','-rn','-o','TARGET,SOURCE,FSTYPE','-T',config['source']],20).decode('ascii').strip().split()
 assert len(raw)==3 and raw[0]==config['source'] and raw[2]=='xfs','Source is not the expected mounted XFS'
 assert run(['blkid','-s','UUID','-o','value',raw[1]],20).decode('ascii').strip()==config['uuid']
 return iscsi_device_binding(raw[1],config)
# 【中文注释】函数 upload：客户端捕获普通文件并上传，或读取对应回执；前后树不一致不能发布为成功。
def upload(config,force=False):
 protected(config['work']);metric(config,'upload',2);source_identity=source_ready(config)
 previous_path=config['work']+'/last-upload.json'
 previous=load(previous_path) if os.path.isfile(previous_path) else {}
 if previous and not force and time.time()-previous['uploaded_timestamp']<86400:
  receipt_path=config['work']+'/receipt.json'
  try:
   run(['rsync','-t','--checksum','--timeout=15','--password-file='+config['password_file'],'lun01backup@192.0.2.30::lun01_receipt/state.json',receipt_path],30)
   receipt=load(receipt_path,65536)
   assert all(receipt[k]==previous[k] for k in ('generation','archive_sha256','manifest_sha256'))
   previous['verified_timestamp']=receipt['verified_timestamp']
   metric(config,'upload',1,previous)
   return {'status':'confirmed_recent','generation':previous['generation'],'verified_timestamp':previous['verified_timestamp']}
  # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
  except Exception:
   metric(config,'upload',1)
   return {'status':'uploaded_awaiting_confirmation','generation':previous['generation']}
 started=int(time.time());before=tree(config['source']);logical=sum(x.get('size',0) for x in before['entries'].values());assert logical<=10*1024**3
 require_staging_capacity(dict(config,role='upload'),logical+len(before['entries'])*2048+32*1024**2,len(before['entries'])+8)
 generation=max(int(time.time()*1000000),previous.get('generation',0)+1)
 stage=config['work']+'/stage-'+str(generation);assert not os.path.exists(stage);os.mkdir(stage,0o700)
 try:
  logical=sum(x.get('size',0) for x in before['entries'].values());assert logical<=10*1024**3
  free=os.statvfs(config['work']);assert free.f_bavail*free.f_frsize>logical+512*1024**2
  archive=stage+'/snapshot.tar'
  # GNU sparse 0.1 is readable by the installed Python 2.7 tar header validator.
  run(['tar','--format=pax','--sparse-version=0.1','--acls','--xattrs','--xattrs-include=user.*','--sparse','--numeric-owner','--one-file-system','--exclude=./.codex_joint_*','-cpf',archive,'-C',config['source'],'.'])
  # 【中文注释】现场前置守卫：角色、复制和无写窗口必须符合本次范围，不能以force绕过。
  assert source_ready(config)==source_identity,'Mounted source binding changed during capture'
  after=tree(config['source']);assert before==after,'Source changed during capture'
  manifest={'schema':1,'source':'client-linux-01','source_uuid':config['uuid'],'generation':generation,'source_capture_started':started,'source_capture_finished':int(time.time()),'source_binding':source_identity,'tree':before}
  atomic(stage+'/manifest.json',manifest)
  ready={'schema':1,'generation':generation,'archive_sha256':digest(archive),'manifest_sha256':digest(stage+'/manifest.json')}
  atomic(stage+'/ready.json',ready)
  validate_archive(archive,manifest)
  for name in ('snapshot.tar','manifest.json','ready.json'):
   run(['rsync','-t','--checksum','--timeout=60','--password-file='+config['password_file'],stage+'/'+name,'lun01backup@192.0.2.30::lun01_upload/'+name])
  receipt=dict(ready,uploaded_timestamp=int(time.time()),source_capture_started=started)
  metric(config,'upload',1,receipt);return dict(receipt,status='uploaded')
 # 【中文注释】无论成功或失败都处理本轮清理/释放；仍须遵守内部的目标与未决状态守卫。
 finally:
  if os.path.isdir(stage):remove_owned(stage,config['work'])

# 【中文注释】函数 valid_version：验证LUN正式版本、清单和实际恢复结果，再参与版本/保留判断。
def valid_version(path):
 protected(path);ready,manifest=bundle(path)
 accepted=load(path+'/accepted.json')
 assert all(accepted[k]==ready[k] for k in ('generation','archive_sha256','manifest_sha256'))
 assert type(accepted.get('capture_order')) in INTEGER and 0<accepted['capture_order']<2**53
 assert type(accepted.get('verified_timestamp')) in INTEGER and accepted['verified_timestamp']>0
 assert accepted.get('source_capture_started')==manifest['source_capture_started'] and accepted.get('object_count')==len(manifest['tree']['entries'])
 return ready,manifest
# 【中文注释】函数 version_order：取得该版本的保留排序键；正式发布和重试必须保持顺序定义一致。
def version_order(path):
 return load(path+'/accepted.json')['capture_order']
# 【中文注释】函数 finish_publication：完成已验证暂存的正式发布及版本修剪，覆盖中断后恢复的剩余步骤。
def finish_publication(config,receipt,status):
 names=[n for n in os.listdir(config['history']) if re.match(r'^[1-9][0-9]{0,15}$',n)]
 if len(names)>7:
  for name in names:valid_version(config['history']+'/'+name)
  names.sort(key=lambda n:version_order(config['history']+'/'+n))
  keep=names[-7:]
  if str(receipt['generation']) not in keep:
   receipt=load(config['history']+'/'+keep[-1]+'/accepted.json');status='superseded_valid'
  for name in names[:-7]:remove_owned(config['history']+'/'+name,config['history'])
 atomic(config['receipt']+'/state.json',receipt,0o640);os.chown(config['receipt']+'/state.json',0,config['receipt_gid'])
 metric(config,'publish',1,receipt);return dict(receipt,status=status)
# 【中文注释】函数 publish：备份端校验入站包并独立恢复后发布正式历史/回执，处理重试及保留范围。
def publish(config):
 protected(config['work']);protected(config['history'])
 incoming=config['incoming'];marker=incoming+'/ready.json'
 if not os.path.isfile(marker):
  metric(config,'publish',2);return {'status':'waiting_for_package'}
 metric(config,'publish',2);ready=load(marker,65536)
 assert type(ready.get('generation')) in INTEGER and 0<ready['generation']<2**53
 identifier=str(ready['generation']);final=config['history']+'/'+identifier
 if os.path.exists(final):
  saved,manifest=valid_version(final);assert saved==ready
  return finish_publication(config,load(final+'/accepted.json'),'existing_valid')
 incoming_manifest=load(incoming+'/manifest.json')
 logical=sum(x.get('size',0) for x in incoming_manifest['tree']['entries'].values());assert 0<=logical<=10*1024**3
 reserve=logical+sum(os.lstat(incoming+'/'+n).st_size for n in ('snapshot.tar','manifest.json','ready.json'))+32*1024**2
 require_staging_capacity(dict(config,role='publish'),reserve,len(incoming_manifest['tree']['entries'])+16)
 stage=config['history']+'/.stage-'+identifier
 if os.path.exists(stage):
  # The CLI holds the job lock. Preserve interrupted staging for diagnosis;
  # Admission counts these artifacts; explicit fingerprinted cleanup is available.
  protected(stage)
  quarantine=config['history']+'/.interrupted-'+identifier+'-'+str(int(time.time()*1000000))
  # 【中文注释】存在性守卫：拒绝覆盖旧结果/已有对象，或拒绝依赖缺失；看条件正负方向。
  assert not os.path.exists(quarantine);os.rename(stage,quarantine)
 os.mkdir(stage,0o700)
 try:
  for name in ('snapshot.tar','manifest.json','ready.json'):
   path=incoming+'/'+name
   fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);s=os.fstat(fd)
   # 【中文注释】身份/路径/权限守卫：只允许本轮授权对象，阻止链接、替换或跨目录操作。
   assert stat.S_ISREG(s.st_mode) and s.st_size<=10*1024**3
   with os.fdopen(fd,'rb') as src:
    with open(stage+'/'+name,'wb') as dst:shutil.copyfileobj(src,dst,1048576)
   os.chmod(stage+'/'+name,0o600)
  ready,manifest=bundle(stage);assert ready==load(marker,65536),'Completion marker changed'
  logical=validate_archive(stage+'/snapshot.tar',manifest);v=os.statvfs(config['history'])
  assert v.f_bavail*v.f_frsize>logical+512*1024**2
  restore_verified(stage+'/snapshot.tar',manifest,stage+'/restore')
  remove_owned(stage+'/restore',stage)
  versions=sorted((n for n in os.listdir(config['history']) if re.match(r'^[1-9][0-9]{0,15}$',n)),key=lambda n:version_order(config['history']+'/'+n))
  for name in versions:valid_version(config['history']+'/'+name)
  keep=versions[-6:];size=os.path.getsize(stage+'/snapshot.tar')+sum(os.path.getsize(config['history']+'/'+n+'/snapshot.tar') for n in keep)
  assert size<=10*1024**3,'History budget exceeded; old versions retained'
  capture_order=max(int(time.time()*1000000),max([version_order(config['history']+'/'+n) for n in versions]+[0])+1)
  receipt=dict(ready,verified_timestamp=int(time.time()),capture_order=capture_order,source_capture_started=manifest['source_capture_started'],object_count=len(manifest['tree']['entries']))
  atomic(stage+'/accepted.json',receipt)
  run(['sync']);os.rename(stage,final);stage=None
  return finish_publication(config,receipt,'created')
 # 【中文注释】无论成功或失败都处理本轮清理/释放；仍须遵守内部的目标与未决状态守卫。
 finally:
  if stage and os.path.isdir(stage):remove_owned(stage,config['history'])

# 【中文注释】函数 self_check：执行源码规定的自检路径；假后端/隔离样本不能当作真实现场故障通过。
def self_check():
 assert safe_name('./folder/a')=='folder/a' and safe_name('.')=='.'
 for name in ('../escape','/absolute','a/../../escape'):
  try:safe_name(name)
  # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
  except AssertionError:pass
  else:raise AssertionError('Unsafe archive path accepted')
 sample=tarfile.TarInfo('sparse-placeholder');sample.pax_headers={'GNU.sparse.name':'./sparse.bin','GNU.sparse.size':'8388608'}
 assert archive_name(sample)=='sparse.bin' and archive_size(sample)==8388608
 sample.pax_headers['GNU.sparse.name']='../../outside'
 try:archive_name(sample)
 # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
 except AssertionError:pass
 else:raise AssertionError('Unsafe GNU sparse path accepted')
 print('LUN_FILE_BACKUP_SELF_CHECK=pass')
# 【中文注释】脚本执行入口；只有本分支受main判断保护，前面的顶层语句仍可能在导入时执行。
if __name__=='__main__':
 if sys.argv[1:]==['--self-check']:self_check();sys.exit(0)
 import fcntl
 config=load('/etc/lun01-file-backup.json',65536);kind=config['role']
 args=sys.argv[1:]
 assert (args in ([],['--force'],['--staging-report']) or (len(args)==4 and args[0]=='--discard-stage')) and kind in ('upload','publish')
 protected(config['work']);lock=open(config['work']+'/job.lock','a');os.chmod(config['work']+'/job.lock',0o600)
 flags=fcntl.fcntl(lock.fileno(),fcntl.F_GETFD);fcntl.fcntl(lock.fileno(),fcntl.F_SETFD,flags & ~fcntl.FD_CLOEXEC)
 try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
 except (IOError,OSError) as error:
  import errno
  if error.errno in (errno.EAGAIN,errno.EWOULDBLOCK):
   print(json.dumps({'status':'busy_skipped','kind':kind}));sys.exit(0)
  raise
 try:
  if args==['--staging-report']:value=staging_report(config)
  elif args and args[0]=='--discard-stage':value=discard_staging(config,args[1],args[2],args[3])
  else:value=upload(config,args==['--force']) if kind=='upload' else publish(config)
  print(json.dumps(value))
 # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
 except Exception as error:
  if args!=['--staging-report'] and not (args and args[0]=='--discard-stage'):metric(config,kind,0)
  print(json.dumps({'status':'failed','error_type':type(error).__name__,'kind':kind}))
  sys.exit(1)
