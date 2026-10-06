#!/usr/bin/python
# -*- coding: utf-8 -*-
# 【中文注释】用途：三共享备份代号运行/历史版本：生成证书、绑定清单、发布同代验证指标。
# 【中文注释】阅读副本：原版与原SHA保留；依赖源码哈希/AST抽取的驱动应执行验证过的原版。
# 【中文注释】顺序：先看常量/配置 → 关键函数 → 顶层或main入口 → 异常与清理。
# 【中文注释】历史版本能力按函数体/所属阶段判定，不能把新增守卫倒写到旧版。
# 发布版保留assert身份/准入守卫，拒绝-O/-OO以免移除这些条件。
if not __debug__:
    raise RuntimeError('Optimized Python disables safety guards; refused')
import glob,hashlib,json,os,re,socket,sys,time,stat

ROLES=('design','dev','finance')
# 【中文注释】函数 regular：以禁止跟随链接的方式读取元数据；新版还拒绝FIFO/特殊文件，具体看下面的打开标志。
def regular(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 if not stat.S_ISREG(os.fstat(fd).st_mode):
  os.close(fd);raise ValueError('Metadata must be a regular file')
 return os.fdopen(fd,'rb')
# 【中文注释】函数 digest：读取文件内容计算摘要；实际算法、读取边界和常规文件守卫以该版本函数体为准。
def digest(path):
 h=hashlib.sha256()
 with regular(path) as f:
  while True:
   block=f.read(65536)
   if not block:break
   h.update(block)
 return h.hexdigest()
# 【中文注释】函数 load：读取JSON状态或配置；该版本如何处理缺失、损坏、大小上限见异常分支。
def load(path):
 try:
  with regular(path) as f:
   if os.fstat(f.fileno()).st_size>16384:return {}
   return json.load(f)
 # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
 except (IOError,OSError,ValueError):return {}
# 【中文注释】函数 certificate：校验源完成证书的字段、节点、代号及各清单摘要，布尔值不能充当整数代号。
def certificate(data):
 return (isinstance(data,dict) and type(data.get('schema')) is int and data.get('schema')==1
  and type(data.get('generation')) in (int,long) and 0<data['generation']<2**53
  and isinstance(data.get('node'),basestring) and re.match(r'^stor-svc-0[12]\Z',data['node'])
  and type(data.get('completed_timestamp')) in (int,long) and data['completed_timestamp']>0
  and isinstance(data.get('source_manifests'),dict) and set(data['source_manifests'])==set(ROLES)
  and all(isinstance(data['source_manifests'][r],basestring) and re.match(r'^[0-9a-f]{64}\Z',data['source_manifests'][r]) for r in ROLES))
# 【中文注释】函数 atomic：先写同目录暂存文件并刷盘，再用重命名发布，避免读到半份状态。
def atomic(path,text,mode):
 stage=path+'.tmp.'+str(os.getpid())
 fd=os.open(stage,os.O_WRONLY|os.O_CREAT|os.O_EXCL,mode)
 try:
  # 【中文注释】刷盘该文件/状态，减少进程中断时只留下内存成功的风险。
  with os.fdopen(fd,'w') as f:f.write(text);f.flush();os.fsync(f.fileno())
  os.rename(stage,path)
 # 【中文注释】无论成功或失败都处理本轮清理/释放；仍须遵守内部的目标与未决状态守卫。
 finally:
  # 【中文注释】删除或清理此对象；必须先满足上方的所有权、真实路径或本轮标识检查。
  if os.path.exists(stage):os.unlink(stage)
# 【中文注释】函数 save：把本轮结果/状态写入固定证据入口；调用者必须先保证不覆盖旧证据。
def save(path,data):atomic(path,json.dumps(data,sort_keys=True)+'\n',0600)
# 【中文注释】函数 create：创建该流程需要的证书/账号/测试对象；具体对象和后置验证见参数及函数体。
def create(directory):
 node=socket.gethostname().split('.')[0];assert re.match(r'^stor-svc-0[12]$',node)
 prior=load(directory+'/generation.json')
 generation=max(int(time.time()*1000000),prior['generation']+1 if certificate(prior) else 1)
 data={'schema':1,'generation':generation,'node':node,'completed_timestamp':int(time.time()),
       'source_manifests':dict((r,digest(directory+'/'+r+'.md5')) for r in ROLES)}
 assert certificate(data)
 save(directory+'/generation.json',data);print(generation)
# 【中文注释】函数 mark：将这次备份端清单绑定到源完成证书，供后续同代校验使用。
def mark(directory,date):
 assert re.match(r'^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$',date)
 source=directory+'/source/generation.json';data=load(source);valid=certificate(data)
 mark={'schema':1,'generation':data['generation'] if valid else 0,'node':data['node'] if valid else 'unknown',
       'source_certificate_sha256':digest(source) if valid else '', 'manifests':{}}
 for r in ROLES:
  name=r+'_'+date+'.md5';mark['manifests'][r]={'file':name,'sha256':digest(directory+'/'+name)}
 save(directory+'/manifest-generation.json',mark)
# 【中文注释】函数 verify：核对本轮清单/源代号并发布同代结果；此版本的具体字段检查按函数体判断。
def verify(directory,metrics):
 source=directory+'/source/generation.json';data=load(source);mark=load(directory+'/manifest-generation.json')
 valid=certificate(data)
 if valid:
  valid=(isinstance(mark,dict) and mark.get('schema')==1 and mark.get('generation')==data['generation']
   and mark.get('node')==data['node'] and mark.get('source_certificate_sha256')==digest(source)
   and isinstance(mark.get('manifests'),dict) and set(mark['manifests'])==set(ROLES))
 node=data['node'] if certificate(data) else 'unknown';now=int(time.time());lines=[]
 for r in ROLES:
  src=directory+'/source/'+r+'.md5';choices=sorted(glob.glob(directory+'/'+r+'_*.md5'))
  target=choices[-1] if choices else '';item=mark.get('manifests',{}).get(r,{}) if isinstance(mark,dict) else {}
  safe_name=isinstance(item,dict) and isinstance(item.get('file'),basestring) and re.match(r'^'+r+r'_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.md5\Z',item['file'])
  if valid and safe_name:target=directory+'/'+item['file']
  matched=False;verified=False
  try:
   a=digest(src);b=digest(target);matched=a==b
   verified=bool(valid and safe_name and matched and a==data['source_manifests'][r] and b==item.get('sha256'))
  # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
  except (IOError,OSError,ValueError):pass
  lines+=['backup_md5_match{name="'+r+'"} '+str(int(matched)),
          'backup_md5_check_timestamp{name="'+r+'"} '+str(now),
          'backup_generation_verified{name="'+r+'"} '+str(int(verified)),
          'backup_verified_generation{name="'+r+'",node="'+node+'"} '+str(data['generation'] if verified else 0)]
 atomic(metrics+'/md5_compare.prom','\n'.join(lines)+'\n',0644)
# 【中文注释】脚本执行入口；只有本分支受main判断保护，前面的顶层语句仍可能在导入时执行。
if __name__=='__main__':
 action=sys.argv[1]
 if action=='create' and len(sys.argv)==3:create(sys.argv[2])
 elif action=='mark' and len(sys.argv)==4:mark(sys.argv[2],sys.argv[3])
 elif action=='verify' and len(sys.argv)==4:verify(sys.argv[2],sys.argv[3])
 else:raise ValueError('Expected create directory, mark directory date, or verify directory metrics')
