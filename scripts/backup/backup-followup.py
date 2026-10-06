#!/usr/bin/python
# -*- coding: utf-8 -*-
# 【中文注释】用途：备份后续联动的运行/历史版本：稳定证书、同代校验、串行任务和指标发布。
# 【中文注释】阅读副本：原版与原SHA保留；依赖源码哈希/AST抽取的驱动应执行验证过的原版。
# 【中文注释】顺序：先看常量/配置 → 关键函数 → 顶层或main入口 → 异常与清理。
# 【中文注释】历史版本能力按函数体/所属阶段判定，不能把新增守卫倒写到旧版。
"""Follow completed source certificates; serialize existing manifest/verify units."""
from __future__ import print_function
# 发布版保留assert身份/准入守卫，拒绝-O/-OO以免移除这些条件。
if not __debug__:
    raise RuntimeError('Optimized Python disables safety guards; refused')
import os,json,re,time,subprocess,stat,sys

META='/backup/checksums'
STATE='/var/lib/backup-followup'
METRICS='/var/lib/node_exporter/textfile_collector'
HISTORY='/backup/.history'
MANIFEST='backup-manifest.service'
VERIFY='verification.service'
STABLE_SECONDS=30
RECHECK_SECONDS=86400
G=None;H=None


# 【中文注释】函数 one_metric：要求指定名称/标签只出现唯一预期值，拒绝重复或陈旧混杂的采集结果。
def one_metric(text,name,labels,value):
    if not isinstance(text,str):text=text.decode('ascii')
    rows=re.findall(r'^'+re.escape(name+'{'+labels+'}')+r' ([0-9]+)$',text,re.M)
    return rows==[str(value)]


# 【中文注释】函数 _marker_valid：验证清单标记与本代证书、源/备端各份摘要是否一致。
def _marker_valid(cert):
    mark=G.load(META+'/manifest-generation.json')
    if not (isinstance(mark,dict) and type(mark.get('schema')) is int and mark.get('schema')==1 and mark.get('generation')==cert['generation']
            and mark.get('node')==cert['node']
            and mark.get('source_certificate_sha256')==G.digest(META+'/source/generation.json')
            and set(mark.get('manifests',{}))==set(G.ROLES)):
        return False
    for role in G.ROLES:
        row=mark['manifests'][role]
        if not isinstance(row,dict):return False
        name=row.get('file','')
        if not re.match(r'^'+role+r'_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.md5\Z',name):return False
        if not (G.digest(META+'/source/'+role+'.md5')==G.digest(META+'/'+name)
                ==row.get('sha256')==cert['source_manifests'][role]):return False
    return True


# 【中文注释】函数 marker_valid：把清单元数据异常转为未验证，而不是当作已经完成。
def marker_valid(cert):
    try:return _marker_valid(cert)
    # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
    except (IOError,OSError,ValueError,KeyError,TypeError,AttributeError):return False


# 【中文注释】函数 ready：检查该流程所需的就绪证据；成功必须满足所有对应字段，不能只看一条状态。
def ready(cert):
    if not marker_valid(cert):return False
    try:
        with G.regular(METRICS+'/md5_compare.prom') as f:text=f.read(65537)
    # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
    except (IOError,OSError,ValueError):return False
    if len(text)>65536:return False
    for role in G.ROLES:
        labels='name="'+role+'"'
        if not (one_metric(text,'backup_md5_match',labels,1)
                and one_metric(text,'backup_generation_verified',labels,1)
                and one_metric(text,'backup_verified_generation',labels+',node="'+cert['node']+'"',cert['generation'])):
            return False
    return True


# 【中文注释】函数 publish：原子发布后续联动指标，保留真实旧成功时间，不在重复跳过时假刷新成功。
def publish(status,state,started=None):
    values={'backup_followup_status':status,'backup_followup_checked_timestamp':int(time.time()),
            'backup_followup_last_success_timestamp':state.get('last_success_timestamp',0),
            'backup_followup_completed_generation':state.get('completed_generation',0),
            'backup_followup_started_timestamp':started or state.get('attempt_started_timestamp',0)}
    G.atomic(METRICS+'/backup_followup.prom','\n'.join(k+' '+str(values[k]) for k in sorted(values))+'\n',0o644)


# 【中文注释】函数 unit：启动指定systemd单位并核对真实退出码/Result；调用者负责串行次序和后续数据验真。
def unit(name):
    # 【中文注释】启动具体命令/子进程；权限、目标和超时见参数，成功还要核对后置证据。
    p=subprocess.Popen(['/usr/bin/timeout','-k','5','1800','systemctl','start',name],
                       stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    p.communicate()
    if p.returncode:raise RuntimeError('followup_unit_failed')
    # 【中文注释】启动具体命令/子进程；权限、目标和超时见参数，成功还要核对后置证据。
    p=subprocess.Popen(['systemctl','show',name,'-p','Result','-p','ExecMainStatus'],
                       stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    a,b=p.communicate()
    if not isinstance(a,str):a=a.decode('ascii')
    if p.returncode or not re.search(r'^Result=success$',a,re.M) or not re.search(r'^ExecMainStatus=0$',a,re.M):
        raise RuntimeError('followup_unit_result_failed')


# 【中文注释】函数 monotonic：读取单调时间，避免系统校时让期限或观察窗口倒退。
def monotonic():
    return time.monotonic() if hasattr(time,'monotonic') else float(open('/proc/uptime').read().split()[0])


# 【中文注释】函数 boot_id：读取启动标识，防止重启后沿用旧单调观察时刻。
def boot_id():return open('/proc/sys/kernel/random/boot_id').read().strip()


# 【中文注释】函数 tick：完成一轮证书观察、去重或后续任务；未验真不能更新本轮成功。
def tick():
    state=G.load(STATE+'/state.json')
    source=META+'/source/generation.json';cert=G.load(source)
    if not G.certificate(cert) or cert['completed_timestamp']>int(time.time()):
        raise ValueError('source_certificate_invalid')
    fingerprint=G.digest(source)
    for role in G.ROLES:
        if G.digest(META+'/source/'+role+'.md5')!=cert['source_manifests'][role]:
            raise ValueError('source_manifests_not_complete')
    boot=boot_id()
    nowmono=monotonic()
    if state.get('observed_certificate')!=fingerprint or state.get('observed_boot_id')!=boot:
        state.update(observed_certificate=fingerprint,observed_boot_id=boot,observed_since_monotonic=nowmono,
                     attempt_started_timestamp=int(time.time()))
        G.save(STATE+'/state.json',state);publish(2,state)
        return {'status':'waiting_stable_certificate','generation':cert['generation']}
    age=nowmono-state.get('observed_since_monotonic',nowmono)
    if not 0<=age:
        raise ValueError('monotonic_observation_invalid')
    if age<STABLE_SECONDS:
        publish(2,state);return {'status':'waiting_stable_certificate','generation':cert['generation']}
    snapshot=HISTORY+'/'+cert['node']+'_'+str(cert['generation'])
    checkpoint=snapshot+'/checkpoint.json'
    complete=ready(cert)
    if complete and state.get('completed_certificate')==fingerprint and state.get('checkpoint_sha256')==G.digest(checkpoint):
        since=int(time.time())-state.get('last_success_timestamp',0)
        if 0<=since<RECHECK_SECONDS:
            publish(1,state);return {'status':'already_complete','generation':cert['generation'],'units_run':[]}
    # Adopt a previously verified version once, without refreshing original success timestamps.
    adopted=False
    if complete and os.path.isdir(snapshot) and state.get('completed_certificate')!=fingerprint:
        record=H.snapshot_valid(snapshot)
        if record['source']!=cert:raise ValueError('history_source_mismatch')
        completed=record['captured_timestamp'];adopted=True
    else:
        state['attempt_started_timestamp']=int(time.time());G.save(STATE+'/state.json',state);publish(2,state)
        unit(MANIFEST)
        if G.digest(source)!=fingerprint or not marker_valid(cert):
            raise ValueError('source_changed_after_manifest')
        unit(VERIFY)
        if G.digest(source)!=fingerprint or not ready(cert):
            raise ValueError('generation_verification_not_complete')
        record=H.snapshot_valid(snapshot)
        if record['source']!=cert:raise ValueError('history_source_mismatch')
        completed=int(time.time())
    if G.digest(source)!=fingerprint:raise ValueError('source_changed_after_history')
    state.update(completed_certificate=fingerprint,completed_generation=cert['generation'],
                 checkpoint_sha256=G.digest(checkpoint),last_success_timestamp=completed)
    G.save(STATE+'/state.json',state);publish(1,state)
    return {'status':'adopted_verified_generation' if adopted else 'completed',
            'generation':cert['generation'],'snapshot':os.path.basename(snapshot),
            'units_run':[] if adopted else [MANIFEST,VERIFY]}


# 【中文注释】函数 main：程序入口：解析参数/标准输入并按分支执行；导入安全性仍取决于模块顶层代码。
def main():
    global G,H
    import imp,fcntl
    G=imp.load_source('followup_generation','/usr/local/bin/backup-generation.py')
    H=imp.load_source('followup_history','/usr/local/bin/backup-history.py')
    # 【中文注释】身份/路径/权限守卫：只允许本轮授权对象，阻止链接、替换或跨目录操作。
    assert os.geteuid()==0 and not os.path.islink(STATE) and os.path.realpath(STATE)==STATE
    s=os.stat(STATE);assert s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700
    path=STATE+'/followup.lock'
    fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600);lock=os.fdopen(fd,'r+')
    metadata=os.fstat(fd)
    # 【中文注释】身份/路径/权限守卫：只允许本轮授权对象，阻止链接、替换或跨目录操作。
    assert stat.S_ISREG(metadata.st_mode) and metadata.st_uid==0
    try:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
        except IOError:
            print(json.dumps({'status':'busy'}));return 0
        try:
            result=tick();print(json.dumps(result,sort_keys=True));return 0
        # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
        except Exception as error:
            publish(0,G.load(STATE+'/state.json'))
            print(json.dumps({'status':'failed','error_type':type(error).__name__}));return 1
    # 【中文注释】无论成功或失败都处理本轮清理/释放；仍须遵守内部的目标与未决状态守卫。
    finally:lock.close()


# 【中文注释】脚本执行入口；只有本分支受main判断保护，前面的顶层语句仍可能在导入时执行。
if __name__=='__main__':sys.exit(main())
