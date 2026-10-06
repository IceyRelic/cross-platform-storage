#!/usr/bin/python
# -*- coding: utf-8 -*-
# 【中文注释】用途：三共享受保护历史运行/历史版本：锁、同代验真、版本发布及保留策略。
# 【中文注释】阅读副本：原版与原SHA保留；依赖源码哈希/AST抽取的驱动应执行验证过的原版。
# 【中文注释】顺序：先看常量/配置 → 关键函数 → 顶层或main入口 → 异常与清理。
# 【中文注释】历史版本能力按函数体/所属阶段判定，不能把新增守卫倒写到旧版。
# 发布版保留assert身份/准入守卫，拒绝-O/-OO以免移除这些条件。
if not __debug__:
    raise RuntimeError('Optimized Python disables safety guards; refused')
import imp,fcntl,time,shutil,uuid,fnmatch,re
G=imp.load_source('history_generation','/usr/local/bin/backup-generation.py')
L=imp.load_source('history_logical','/usr/local/bin/logical-md5-manifest.py')

import hashlib,json,os,stat
# 【中文注释】函数 tree：采集对象树和此版本定义的内容/元数据/硬链接信息；不将目录名相同当作数据相同。
def tree(base):
 entries={}; inodes={}
 for current,dirs,files in os.walk(base,followlinks=False):
  paths=[current] if current==base else []
  paths += [os.path.join(current,n) for n in dirs+files]
  for p in paths:
   rel=os.path.relpath(p,base); s=os.lstat(p)
   item={'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'mtime_seconds':int(s.st_mtime)}
   if stat.S_ISREG(s.st_mode):
    h=hashlib.sha256()
    with open(p,'rb') as f:
     while True:
      block=f.read(1048576)
      if not block: break
      h.update(block)
    item.update({'type':'file','size':s.st_size,'sha256':h.hexdigest()})
    inodes.setdefault((s.st_dev,s.st_ino),[]).append(rel)
   elif stat.S_ISLNK(s.st_mode): item.update({'type':'symlink','target':os.readlink(p)})
   elif stat.S_ISDIR(s.st_mode): item['type']='directory'
   else: item['type']='special'; item['rdev']=s.st_rdev
   entries[rel]=item
 return {'entries':entries,'hardlink_groups':sorted(sorted(v) for v in inodes.values() if len(v)>1)}

import fnmatch,subprocess
# 【中文注释】函数 policy_tree：按业务共享的排除规则取对象树，并检查ACL/user xattr等元数据。
def policy_tree(base,role):
 data=tree(base)
 # 【中文注释】函数 included：判断路径是否属于业务数据；dev的NFS运行状态排除规则不能泛化到所有共享。
 def included(rel):
  if role!='dev': return True
  return not (rel=='nfsinfo' or rel.startswith('nfsinfo/') or any(fnmatch.fnmatch(os.path.basename(rel),p) for p in ('.rmtab*','.etab*','.xtab*')))
 data['entries']={r:v for r,v in data['entries'].items() if included(r)}
 data['hardlink_groups']=[g for g in [sorted(r for r in group if included(r)) for group in data['hardlink_groups']] if len(g)>1]
 for rel,item in data['entries'].items():
  if item['type'] not in ('file','directory'): continue
  path=os.path.join(base,rel)
  for key,args in [('acl_sha256',['getfacl','-cpn',path]),('user_xattr_sha256',['getfattr','-d','-m','^user\.','-e','hex','--absolute-names',path])]:
   # 【中文注释】启动具体命令/子进程；权限、目标和超时见参数，成功还要核对后置证据。
   p=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE); text,error=p.communicate()
   assert p.returncode==0
   if key=='user_xattr_sha256': text='\n'.join(sorted(s for s in text.splitlines() if s and not s.startswith('#')))
   item[key]=hashlib.sha256(text).hexdigest()
 return data


ROLES=('design','dev','finance')
# 【中文注释】函数 checked：执行原生命令，非零视为失败，防止后续用不完整输出验收。
def checked(args,cwd=None,data=None):
 # 【中文注释】启动具体命令/子进程；权限、目标和超时见参数，成功还要核对后置证据。
 p=subprocess.Popen(args,cwd=cwd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE);a,b=p.communicate(data)
 if p.returncode:raise RuntimeError('Native history operation failed')
 return a
# 【中文注释】函数 physical：取得物理内容与元数据的比较视图，区别于只对普通文件做逻辑MD5。
def physical(base):return policy_tree(base,'physical')
# 【中文注释】函数 serial_digest：按固定序列化方式计算对象树指纹，用于比较内容/元数据。
def serial_digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True)).hexdigest()
# 【中文注释】函数 included：判断路径是否属于业务数据；dev的NFS运行状态排除规则不能泛化到所有共享。
def included(role,rel):
 return role!='dev' or not (rel.startswith('nfsinfo/') or any(fnmatch.fnmatch(os.path.basename(rel),x) for x in ('.rmtab*','.etab*','.xtab*')))
# 【中文注释】函数 logical_md5：筛选逻辑普通文件，按稳定次序生成MD5结果，遵守本共享排除范围。
def logical_md5(base,role):
 files=[]
 for current,dirs,names in os.walk(base,followlinks=False):
  for name in names:
   rel=os.path.relpath(current+'/'+name,base)
   if included(role,rel) and L.logical_regular(current+'/'+name):files.append('./'+rel)
 lines=[]
 for name in sorted(files):lines.append(checked(['md5sum','--',name],cwd=base))
 return checked(['sort'],data=''.join(lines))
# 【中文注释】函数 protected：验证私有目录的真实路径、root属主和权限；不能借符号链接扩大操作范围。
def protected(path):
 s=os.lstat(path);assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0700 and os.path.realpath(path)==path
# 【中文注释】函数 snapshot_valid：校验历史checkpoint与实际历史对象树，损坏版本不能冒充成功或直接被淘汰。
def snapshot_valid(path):
 protected(path);data=G.load(path+'/checkpoint.json')
 assert type(data.get('schema')) is int and data['schema']==1 and G.certificate(data.get('source',{})) and set(data.get('trees',{}))==set(ROLES)
 capture_order(data)
 assert os.path.basename(path)==data['source']['node']+'_'+str(data['source']['generation'])
 assert data['trees']==dict((r,serial_digest(physical(path+'/shares/'+r))) for r in ROLES)
 return data
# 【中文注释】函数 version_names：只列出符合正式版本命名格式的候选，不把暂存目录当成历史版本。
def version_names(root):
 return [n for n in os.listdir(root) if re.match(r'^stor-svc-0[12]_[1-9][0-9]{0,15}\Z',n)]
# 【中文注释】函数 capture_order：取得真实捕获顺序；解决双节点时钟/代号排序不能替代备端捕获时间的问题。
def capture_order(data):
 stamp=data.get('captured_timestamp');assert type(stamp) in (int,long) and stamp>0
 value=data.get('capture_order',stamp*1000000)
 assert type(value) in (int,long) and 0<value<2**53
 return value
# 【中文注释】函数 versions：依据本版本的排序规则列出历史；不能把字符串排序等同真实创建次序。
def versions(root):
 return sorted(version_names(root),key=lambda n:(capture_order(G.load(root+'/'+n+'/checkpoint.json')),n))
# 【中文注释】函数 trim：先验证所有候选旧版本，再删除超保留范围的历史，拒绝用损坏历史继续滚动。
def trim(root,retain):
 victims=versions(root)[:-retain]
 for name in victims:snapshot_valid(root+'/'+name)
 for name in victims:
  # 【中文注释】删除或清理此对象；必须先满足上方的所有权、真实路径或本轮标识检查。
  victim=root+'/'+name;assert os.path.dirname(os.path.realpath(victim))==root;shutil.rmtree(victim)
 return victims
# 【中文注释】函数 metric：发布本轮状态及真实历史成功时间；失败不能刷新旧成功为新成功。
def metric(path,status,snapshot=None,count=0,limit=7):
 now=int(time.time());lines=['backup_history_capture_status '+str(status),'backup_history_attempt_timestamp '+str(now),'backup_history_snapshot_count '+str(count),'backup_history_retention_limit '+str(limit)]
 if snapshot:lines+=['backup_history_source_generation '+str(snapshot['source']['generation']),'backup_history_source_completed_timestamp '+str(snapshot['source']['completed_timestamp']),'backup_history_created_timestamp '+str(snapshot['captured_timestamp'])]
 G.atomic(path,'\n'.join(lines)+'\n',0644)
# 【中文注释】函数 capture：在锁和同代守卫下捕获三共享；暂存验真后发布，最后修剪并更新指标。
def capture(current,metadata,root,metric_file,retain=7):
 assert type(retain) is int and 1<=retain<=30
 if not os.path.exists(root):os.mkdir(root,0700)
 protected(root);lock=open(root+'/capture.lock','a');os.chmod(root+'/capture.lock',0600);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 stage=None
 try:
  metric(metric_file,2,count=len(versions(root)),limit=retain)
  source=G.load(metadata+'/source/generation.json');assert G.certificate(source) and source['completed_timestamp']<=int(time.time())
  marker=G.load(metadata+'/manifest-generation.json')
  assert type(marker.get('schema')) is int and marker['schema']==1 and marker.get('generation')==source['generation'] and marker.get('node')==source['node'] and marker.get('source_certificate_sha256')==G.digest(metadata+'/source/generation.json')
  assert set(marker.get('manifests',{}))==set(ROLES)
  for role in ROLES:
   name=marker['manifests'][role]['file'];assert re.match(r'^'+role+r'_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.md5\Z',name)
   expected=source['source_manifests'][role]
   assert G.digest(metadata+'/source/'+role+'.md5')==G.digest(metadata+'/'+name)==marker['manifests'][role]['sha256']==expected
   assert hashlib.sha256(logical_md5(current[role],role)).hexdigest()==expected
  identifier=source['node']+'_'+str(source['generation']);final=root+'/'+identifier
  if os.path.exists(final):
   data=snapshot_valid(final);assert data['source']==source
   trim(root,retain)
   metric(metric_file,1,data,len(versions(root)),retain);return {'status':'existing_valid','snapshot':identifier,'count':len(versions(root))}
  before=dict((r,physical(current[r])) for r in ROLES)
  size=sum(item.get('size',0) for value in before.values() for item in value['entries'].values());assert size<10*1024**3
  free=os.statvfs(root);assert free.f_bavail*free.f_frsize>max(size*2,512*1024**2)
  stage=root+'/.partial-'+uuid.uuid4().hex;os.mkdir(stage,0700);os.mkdir(stage+'/shares',0700);os.mkdir(stage+'/metadata',0700)
  for role in ROLES:checked(['cp','-a','--reflink=auto','--sparse=always','--',current[role],stage+'/shares/'+role])
  after=dict((r,physical(current[r])) for r in ROLES);assert before==after
  assert after==dict((r,physical(stage+'/shares/'+r)) for r in ROLES)
  for name in ('source/generation.json','manifest-generation.json'):
   target=stage+'/metadata/'+os.path.basename(name);shutil.copyfile(metadata+'/'+name,target);os.chmod(target,0600)
  for role in ROLES:
   shutil.copyfile(metadata+'/source/'+role+'.md5',stage+'/metadata/'+role+'.md5');os.chmod(stage+'/metadata/'+role+'.md5',0600)
  previous=[capture_order(G.load(root+'/'+n+'/checkpoint.json')) for n in versions(root)]
  order=max(int(time.time()*1000000),max(previous or [0])+1)
  assert order<2**53
  data={'schema':1,'source':source,'captured_timestamp':int(time.time()),'capture_order':order,'trees':dict((r,serial_digest(after[r])) for r in ROLES),'regular_physical_bytes':size,'retention_versions':retain,'comparison':'physical content, numeric ownership, seconds mtime, mode, ACL and user xattrs, hardlinks'}
  G.save(stage+'/checkpoint.json',data)
  # Files and directory entries are durably flushed before publication.
  checked(['sync']);os.rename(stage,final);stage=None
  # 【中文注释】刷盘该文件/状态，减少进程中断时只留下内存成功的风险。
  descriptor=os.open(root,os.O_RDONLY);os.fsync(descriptor);os.close(descriptor);snapshot_valid(final)
  pruned=trim(root,retain)
  metric(metric_file,1,data,len(versions(root)),retain)
  return {'status':'created','snapshot':identifier,'count':len(versions(root)),'pruned':pruned,'source_completed_timestamp':source['completed_timestamp'],'captured_timestamp':data['captured_timestamp'],'physical_bytes':size}
 # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
 except Exception:
  metric(metric_file,0,count=len(version_names(root)),limit=retain);raise
 # 【中文注释】无论成功或失败都处理本轮清理/释放；仍须遵守内部的目标与未决状态守卫。
 finally:
  # 【中文注释】删除或清理此对象；必须先满足上方的所有权、真实路径或本轮标识检查。
  if stage and os.path.isdir(stage):assert os.path.dirname(os.path.realpath(stage))==root and os.path.basename(stage).startswith('.partial-');shutil.rmtree(stage)
  lock.close()
# 【中文注释】函数 self_check：执行源码规定的自检路径；假后端/隔离样本不能当作真实现场故障通过。
def self_check():
 base='/var/tmp/codex_history_check_'+uuid.uuid4().hex;os.mkdir(base,0700);current={};metadata=base+'/checksums';history=base+'/history';metric_file=base+'/test.prom'
 os.mkdir(metadata,0700);os.mkdir(metadata+'/source',0700)
 for role in ROLES:
  current[role]=base+'/'+role;os.mkdir(current[role],0700);open(current[role]+'/sample','w').write('v1\n')
 # 【中文注释】函数 publish：发布本流程的指标/测试证书或阶段对象；测试夹具的发布不等于正式备份发布。
 def publish(number):
  stamp='2026-10-02_12-00-'+str(number).zfill(2);digests={}
  for role in ROLES:
   value=logical_md5(current[role],role);open(metadata+'/source/'+role+'.md5','w').write(value);open(metadata+'/'+role+'_'+stamp+'.md5','w').write(value);digests[role]=hashlib.sha256(value).hexdigest()
  source={'schema':1,'node':'stor-svc-01','generation':number,'completed_timestamp':int(time.time()),'source_manifests':digests};G.save(metadata+'/source/generation.json',source);G.mark(metadata,stamp)
 try:
  publish(1);first=capture(current,metadata,history,metric_file,2);assert first['status']=='created';assert capture(current,metadata,history,metric_file,2)['status']=='existing_valid'
  # 【中文注释】删除或清理此对象；必须先满足上方的所有权、真实路径或本轮标识检查。
  open(current['dev']+'/sample','w').write('v2\n');os.unlink(current['finance']+'/sample')
  assert open(history+'/stor-svc-01_1/shares/dev/sample').read()=='v1\n' and os.path.isfile(history+'/stor-svc-01_1/shares/finance/sample')
  failed=False
  try:capture(current,metadata,history,metric_file,2)
  # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
  except AssertionError:failed=True
  assert failed and versions(history)==['stor-svc-01_1']
  publish(2);capture(current,metadata,history,metric_file,2);publish(3);last=capture(current,metadata,history,metric_file,2)
  assert last['pruned']==['stor-svc-01_1'] and versions(history)==['stor-svc-01_2','stor-svc-01_3']
  open(history+'/stor-svc-01_2/shares/dev/sample','w').write('corrupt\n');publish(4);failed=False
  try:capture(current,metadata,history,metric_file,2)
  # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
  except AssertionError:failed=True
  assert failed and 'stor-svc-01_2' in versions(history)
  failed=False
  try:capture(current,metadata,history,metric_file,2)
  # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
  except AssertionError:failed=True
  assert failed and 'stor-svc-01_2' in versions(history)
  print(json.dumps({'self_check':'pass','idempotence':True,'old_content_and_deleted_file_recoverable':True,'stale_certificate_rejected':True,'bounded_retention':True,'corrupt_old_snapshot_not_deleted':True}))
 # 【中文注释】无论成功或失败都处理本轮清理/释放；仍须遵守内部的目标与未决状态守卫。
 finally:assert os.path.realpath(base)==base and base.startswith('/var/tmp/codex_history_check_');shutil.rmtree(base)
# 【中文注释】脚本执行入口；只有本分支受main判断保护，前面的顶层语句仍可能在导入时执行。
if __name__=='__main__':
 import sys
 try:
  if sys.argv[1:]==['--self-check']:self_check()
  elif not sys.argv[1:]:print(json.dumps(capture(dict((r,'/backup/'+r+'/current') for r in ROLES),'/backup/checksums','/backup/.history','/var/lib/node_exporter/textfile_collector/backup_history.prom')))
  else:raise ValueError('Unexpected arguments')
 # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
 except Exception as e:sys.stderr.write('backup-history failure: '+type(e).__name__+'\n');sys.exit(1)
