# -*- coding: utf-8 -*-
# 【中文注释】用途：本步骤的代码/运行快照；具体职责按下面调用和所属阶段说明核对。
# 【中文注释】阅读副本：原版与原SHA保留；依赖源码哈希/AST抽取的驱动应执行验证过的原版。
# 【中文注释】顺序：先看常量/配置 → 关键函数 → 顶层或main入口 → 异常与清理。
# 【中文注释】历史版本能力按函数体/所属阶段判定，不能把新增守卫倒写到旧版。
"""当前用户会话的控制器监督：单实例、认证TLS/进程身份、持久未决守卫与有界恢复，无VM off接口。"""
# 发布版保留assert身份/准入守卫，拒绝-O/-OO以免移除这些条件。
if not __debug__:
    raise RuntimeError('Optimized Python disables safety guards; refused')
from pathlib import Path
import ctypes,datetime,hashlib,importlib.util,json,math,msvcrt,os,re,socket,ssl,subprocess,sys,time,urllib.request,uuid
from ctypes import wintypes as W

# 桌面进程实测看不到原LocalAppData运行目录；新目录先设ACL，再复制原身份。
PRIVATE=Path.home()/'Documents'/'CodexStorageFencingRuntime'
BROKER_SHA='06ce0a064a5fc03f828c7eca3e0508468ef706383264f159ef467270272991f3'
K=ctypes.WinDLL('kernel32',use_last_error=True)
K.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];K.OpenProcess.restype=W.HANDLE
K.GetExitCodeProcess.argtypes=[W.HANDLE,ctypes.POINTER(W.DWORD)]
K.QueryFullProcessImageNameW.argtypes=[W.HANDLE,W.DWORD,W.LPWSTR,ctypes.POINTER(W.DWORD)]
K.GetProcessTimes.argtypes=[W.HANDLE,ctypes.POINTER(W.FILETIME),ctypes.POINTER(W.FILETIME),ctypes.POINTER(W.FILETIME),ctypes.POINTER(W.FILETIME)]
K.CloseHandle.argtypes=[W.HANDLE]
K.TerminateProcess.argtypes=[W.HANDLE,W.UINT]
S=ctypes.WinDLL('shell32',use_last_error=True)
S.CommandLineToArgvW.argtypes=[W.LPCWSTR,ctypes.POINTER(ctypes.c_int)];S.CommandLineToArgvW.restype=ctypes.POINTER(W.LPWSTR)
K.LocalFree.argtypes=[W.HANDLE]
I=ctypes.WinDLL('iphlpapi',use_last_error=True)
I.GetExtendedTcpTable.argtypes=[W.LPVOID,ctypes.POINTER(W.DWORD),W.BOOL,W.ULONG,ctypes.c_int,W.ULONG];I.GetExtendedTcpTable.restype=W.DWORD
# 【中文注释】将该职责的请求处理/连接状态组织在此类内，具体方法的失败边界见下方。
class Row4(ctypes.Structure):
    _fields_=[(n,W.DWORD) for n in ('state','local_addr','local_port','remote_addr','remote_port','pid')]
# 【中文注释】将该职责的请求处理/连接状态组织在此类内，具体方法的失败边界见下方。
class Row6(ctypes.Structure):
    _fields_=[('local_addr',ctypes.c_ubyte*16),('local_scope',W.DWORD),('local_port',W.DWORD),('remote_addr',ctypes.c_ubyte*16),('remote_scope',W.DWORD),('remote_port',W.DWORD),('state',W.DWORD),('pid',W.DWORD)]

# 【中文注释】函数 process_identity：处理此命名步骤的参数与返回值；具体边界/异常按下方函数体及所属阶段核对。
def process_identity(pid):
    """PID加创建时刻/程序路径识别实例；拒绝访问或PID复用不能当原进程已死。"""
    handle=K.OpenProcess(0x1000|0x100000,False,int(pid))
    if not handle:return {'state':'absent' if ctypes.get_last_error()==87 else 'unknown','pid':pid}
    try:
        code=W.DWORD();assert K.GetExitCodeProcess(handle,ctypes.byref(code))
        if code.value!=259:return {'state':'absent','pid':pid,'exit':code.value}
        length=W.DWORD(32768);image=ctypes.create_unicode_buffer(length.value)
        assert K.QueryFullProcessImageNameW(handle,0,image,ctypes.byref(length))
        created,exited,kernel,user=(W.FILETIME() for _ in range(4))
        assert K.GetProcessTimes(handle,ctypes.byref(created),ctypes.byref(exited),ctypes.byref(kernel),ctypes.byref(user))
        return {'state':'alive','pid':pid,'image':image.value,'creation_filetime':(created.dwHighDateTime<<32)|created.dwLowDateTime}
    # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
    except Exception:return {'state':'unknown','pid':pid}
    # 【中文注释】无论成功或失败都处理本轮清理/释放；仍须遵守内部的目标与未决状态守卫。
    finally:K.CloseHandle(handle)

# 【中文注释】函数 choose：处理此命名步骤的参数与返回值；具体边界/异常按下方函数体及所属阶段核对。
def choose(healthy,process_state,port_state,receipts_clear,pending_clear,rate_ok):
    """纯策略：监督只启动已确认不存在的进程，不结束异常活进程、不绕开未决请求。"""
    if healthy:return 'observe_authenticated_healthy'
    if process_state=='alive':return 'wait_live_controller_unhealthy'
    if process_state!='absent':return 'wait_process_identity_unknown'
    if port_state!='free':return 'wait_port_not_confirmed_free'
    if not receipts_clear:return 'wait_durable_request_unresolved'
    if not pending_clear:return 'wait_daemon_fencing_unresolved_or_unknown'
    if not rate_ok:return 'wait_restart_rate_budget'
    return 'start_existing_controller'

# 【中文注释】函数 current_boot_identity：处理此命名步骤的参数与返回值；具体边界/异常按下方函数体及所属阶段核对。
def current_boot_identity():
    """开机时间按UTC固定同一宿主启动域；仅启动时查询一次，隐藏窗口，不推测任务组独立性。"""
    command="(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')"
    # 【中文注释】启动具体命令/子进程；权限、目标和超时见参数，成功还要核对后置证据。
    p=subprocess.run(['powershell.exe','-NoProfile','-Command',command],capture_output=True,timeout=15,creationflags=subprocess.CREATE_NO_WINDOW)
    assert p.returncode==0
    value=p.stdout.decode('utf-8-sig').strip()
    assert re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z',value),'Boot identity unavailable'
    return value

# 【中文注释】函数 normalize_budget：处理此命名步骤的参数与返回值；具体边界/异常按下方函数体及所属阶段核对。
def normalize_budget(saved,boot,now):
    """只在相同宿主启动域比较monotonic；旧格式不猜来源，保守冷却300秒后再恢复额度。"""
    assert isinstance(saved,dict) and isinstance(boot,str) and boot
    values=saved.get('attempt_monotonic',[])
    assert isinstance(values,list) and len(values)<=3
    assert all(type(v) in (int,float) and math.isfinite(v) and v>=0 for v in values),'Invalid restart budget'
    if saved.get('schema') is None and 'boot_identity' not in saved:
        attempts=[now]*len(values);reason='legacy_budget_conservative_300_second_cooldown'
    else:
        assert type(saved.get('schema')) is int and saved['schema']==1
        assert isinstance(saved.get('boot_identity'),str) and saved['boot_identity']
        if saved['boot_identity']!=boot:attempts=[];reason='different_host_boot_new_monotonic_domain'
        else:
            assert all(v<=now for v in values),'Same-boot future monotonic value; refuse reset'
            attempts=[v for v in values if 0<=now-v<300];reason='same_host_boot_window'
    return {'schema':1,'boot_identity':boot,'attempt_monotonic':attempts},reason

# 【中文注释】函数 owned_tunnels：处理此命名步骤的参数与返回值；具体边界/异常按下方函数体及所属阶段核对。
def owned_tunnels(config,parent_pid):
    """只接受固定父PID、严格SSH argv、原生创建时间；不在日志暴露命令行/认证材料。"""
    command='Get-CimInstance Win32_Process -Filter "ParentProcessId = '+str(int(parent_pid))+'" | Select-Object ProcessId,ParentProcessId,CommandLine | ConvertTo-Json -Compress'
    # 【中文注释】启动具体命令/子进程；权限、目标和超时见参数，成功还要核对后置证据。
    p=subprocess.run(['powershell.exe','-NoProfile','-Command',command],capture_output=True,timeout=10,creationflags=subprocess.CREATE_NO_WINDOW)
    assert p.returncode==0
    raw=p.stdout.decode('utf-8-sig').strip();rows=json.loads(raw) if raw else []
    if isinstance(rows,dict):rows=[rows]
    verified=[]
    for row in rows:
        count=ctypes.c_int();argv=S.CommandLineToArgvW(row['CommandLine'] or '',ctypes.byref(count))
        assert argv
        try:args=[argv[i] for i in range(count.value)]
        # 【中文注释】无论成功或失败都处理本轮清理/释放；仍须遵守内部的目标与未决状态守卫。
        finally:K.LocalFree(ctypes.cast(argv,W.HANDLE))
        matched=False
        for host in ('lab-stor-01','lab-stor-02'):
            expected=config['ssh']+['-N','-T','-o','ExitOnForwardFailure=yes','-o','ServerAliveInterval=15','-o','ServerAliveCountMax=2','-R','127.0.0.1:9447:127.0.0.1:8767',host]
            if args==expected:matched=True
        if matched:
            info=process_identity(row['ProcessId'])
            assert info['state']=='alive' and Path(info['image']).resolve()==Path(config['ssh'][0]).resolve()
            verified.append(info)
    return verified

# 【中文注释】函数 stop_verified_process：处理此命名步骤的参数与返回值；具体边界/异常按下方函数体及所属阶段核对。
def stop_verified_process(info):
    """原生句柄绑定PID+创建时间，只结束已确认旧SSH通道；此函数不查找/结束所有ssh或python。"""
    current=process_identity(info['pid'])
    if current['state']=='absent':return {'pid':info['pid'],'already_absent':True}
    assert current==info,'Process instance changed; refuse termination'
    handle=K.OpenProcess(0x1000|0x100000|1,False,info['pid']);assert handle
    try:
        created,exited,kernel,user=(W.FILETIME() for _ in range(4))
        assert K.GetProcessTimes(handle,ctypes.byref(created),ctypes.byref(exited),ctypes.byref(kernel),ctypes.byref(user))
        assert ((created.dwHighDateTime<<32)|created.dwLowDateTime)==info['creation_filetime']
        assert K.TerminateProcess(handle,0)
    # 【中文注释】无论成功或失败都处理本轮清理/释放；仍须遵守内部的目标与未决状态守卫。
    finally:K.CloseHandle(handle)
    return {'pid':info['pid'],'verified_old_tunnel_stopped':True}

# 【中文注释】函数 save：把本轮结果/状态写入固定证据入口；调用者必须先保证不覆盖旧证据。
def save(path,value):
    # 【中文注释】保存本轮文件/证据；沿用原存在性检查，不覆盖历史事实。
    temp=path.with_suffix('.new');temp.write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8');os.replace(temp,path)

# 【中文注释】函数 log：记录本轮事件/请求关联；不写认证头、令牌或私钥正文。
def log(event,**fields):
    """有限轮换的结构化日志；不包含配置内容/令牌/许可签名/请求正文。"""
    path=PRIVATE/'supervisor-events.jsonl'
    if path.exists() and path.stat().st_size>1048576:
        for i in (2,1):
            old=PRIVATE/('supervisor-events.jsonl.'+str(i));new=PRIVATE/('supervisor-events.jsonl.'+str(i+1))
            if old.exists():os.replace(old,new)
        os.replace(path,PRIVATE/'supervisor-events.jsonl.1')
    with path.open('a',encoding='utf-8') as f:f.write(json.dumps(dict(time_local=datetime.datetime.now().isoformat(),event=event,**fields),ensure_ascii=False)+'\n')

# 【中文注释】函数 tls：处理此命名步骤的参数与返回值；具体边界/异常按下方函数体及所属阶段核对。
def tls(config,context):
    """固定两VM status，只读、每次新nonce、校验认证/策略/UUID/MAC；on/off均是合法平台状态。"""
    rows={}
    for node in ('stor-svc-01','stor-svc-02'):
        nonce=uuid.uuid4().hex
        req=urllib.request.Request('https://localhost:8767/v1/power',data=json.dumps({'action':'status','node':node,'nonce':nonce}).encode(),
            headers={'X-Storage-Caller':'stor-svc-01','Authorization':'Bearer '+config['callers']['stor-svc-01']})
        try:
            with urllib.request.urlopen(req,context=context,timeout=6) as response:r=json.load(response)
            assert r['nonce']==nonce and r['node']==node and r['off_policy']=='automatic_peer_challenge'
            assert r['bios_uuid']==config['mapping'][node]['bios_uuid'] and r['mac']==config['mapping'][node]['mac']
            assert r['power_state'] in ('on','off','paused','suspended')
            rows[node]={'verified':True,'power_state':r['power_state']}
        # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
        except Exception as e:rows[node]={'verified':False,'error_type':type(e).__name__}
    return rows

# 【中文注释】函数 port_state：处理此命名步骤的参数与返回值；具体边界/异常按下方函数体及所属阶段核对。
def port_state():
    """用IPv4/IPv6原生监听所有权表确认，不以短连接超时误判关闭端口未知。"""
    try:
        for family,row_type in ((2,Row4),(23,Row6)):
            size=W.DWORD();rc=I.GetExtendedTcpTable(None,ctypes.byref(size),False,family,5,0)
            assert rc in (0,122) and size.value>=4
            buffer=ctypes.create_string_buffer(size.value)
            assert I.GetExtendedTcpTable(buffer,ctypes.byref(size),False,family,5,0)==0
            count=W.DWORD.from_buffer(buffer).value
            assert 4+count*ctypes.sizeof(row_type)<=size.value
            for index in range(count):
                row=row_type.from_buffer(buffer,4+index*ctypes.sizeof(row_type))
                if socket.ntohs(row.local_port&0xffff)==8767 and row.state==2:return 'occupied'
        return 'free'
    # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
    except Exception:return 'unknown'

# 【中文注释】函数 guest_status：处理此命名步骤的参数与返回值；具体边界/异常按下方函数体及所属阶段核对。
def guest_status(config,host,reprobe=False):
    """仅读公开CIB/实际agent。可重探测时只清两设备，要求两节点clean/唯一业务/无未决。"""
    # 【中文注释】多行资料/远程代码模板；字符串保持原样。代码型片段另见旁边的远程片段解读。
    script=r'''import subprocess,json,re,xml.etree.ElementTree as E
def run(args):
 p=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE);a,b=p.communicate();return p.returncode,a
rc,h=run(['stonith_admin','--history','*','--verbose']);assert rc==0
rc,text=run(['crm_mon','-1','-r']);assert rc==0
rc,cib=run(['cibadmin','--query']);assert rc==0;r=E.fromstring(cib)
props=dict((x.get('name'),x.get('value')) for x in r.findall('./configuration/crm_config//nvpair') if x.get('name') in ('stonith-enabled','stonith-action','no-quorum-policy','maintenance-mode'))
masters=re.findall(r'Masters:\s*\[\s*(stor-svc-0[12])\s*\]',text)
online=re.search(r'Online:\s*\[([^]]+)\]',text)
safe=('wishes to' not in h and 'partition with quorum' in text and online and all(n in online.group(1).split() for n in ('stor-svc-01','stor-svc-02')) and 'UNCLEAN' not in text and 'standby' not in text and len(masters)==4 and len(set(masters))==1 and props=={'stonith-enabled':'true','stonith-action':'off','no-quorum-policy':'stop','maintenance-mode':'false'})
failed=re.findall(r'^\* (fence-stor0[12])_[a-z]+_[0-9]+ .*',text,re.M)
section=text.split('Failed Resource Actions:',1)[-1] if 'Failed Resource Actions:' in text else ''
others=[line for line in section.splitlines() if line.startswith('* ') and not re.match(r'^\* fence-stor0[12]_',line)]
rc,_=run(['/usr/sbin/fence_workstation_lab','--action','monitor'])
actions=[]
if __REPROBE__ and safe and not others and rc==0:
 for name in sorted(set(failed)):
  code,_=run(['pcs','resource','cleanup',name]);actions.append({'resource':name,'exit':code})
print(json.dumps({'history_pending':('wishes to' in h),'safe_clean_two_node_context':bool(safe),'agent_monitor_exit':rc,'failed_devices':sorted(set(failed)),'other_failed_actions':bool(others),'targeted_reprobe':actions}))
'''.replace('__REPROBE__',repr(reprobe))
    body="export LC_ALL=C\npython - <<'PY'\n"+script+"\nPY\n"
    # 【中文注释】启动具体命令/子进程；权限、目标和超时见参数，成功还要核对后置证据。
    p=subprocess.run(config['ssh']+[host,'bash -s'],input=body.encode(),capture_output=True,timeout=45,
                     creationflags=subprocess.CREATE_NO_WINDOW)
    if p.returncode:raise RuntimeError('Guest guard unavailable')
    return json.loads(p.stdout)

# 【中文注释】函数 main：程序入口：解析参数/标准输入并按分支执行；导入安全性仍取决于模块顶层代码。
def main():
    """锁位于已有私有ACL目录，退出时OS释放；每5秒检查，每30秒验证两端，重启最多3/5分钟。"""
    assert PRIVATE.is_dir() and not PRIVATE.is_symlink()
    lock=(PRIVATE/'supervisor.lock').open('a+b')
    if lock.seek(0,2)==0:lock.write(b'0');lock.flush()
    lock.seek(0)
    try:msvcrt.locking(lock.fileno(),msvcrt.LK_NBLCK,1)
    # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
    except OSError:
        lock.close();print(json.dumps({'status':'already_supervised_no_duplicate'}));return
    try:
        source=PRIVATE/'workstation_fencing_broker.py'
        assert hashlib.sha256(source.read_bytes()).hexdigest()==BROKER_SHA,'Controller version changed; audit required'
        spec=importlib.util.spec_from_file_location('installed_broker_policy',source);policy=importlib.util.module_from_spec(spec);spec.loader.exec_module(policy)
        config=json.loads((PRIVATE/'broker-config.json').read_text(encoding='utf-8'))
        assert config['off_policy']=='automatic_peer_challenge'
        context=ssl.create_default_context(cafile=str(PRIVATE/'channel-cert.pem'))
        budget_file=PRIVATE/'supervisor-restart-budget.json'
        boot=current_boot_identity()
        saved_budget=json.loads(budget_file.read_text()) if budget_file.exists() else {'schema':1,'boot_identity':boot,'attempt_monotonic':[]}
        budget,reason=normalize_budget(saved_budget,boot,time.monotonic());attempts=budget['attempt_monotonic']
        save(budget_file,budget);log('restart_budget_domain_checked',reason=reason,boot_identity=boot,attempts=len(attempts))
        next_guest=0;old_state=None;last_guest=None
        supervisor_identity=process_identity(os.getpid());save(PRIVATE/'supervisor.pid.json',supervisor_identity)
        log('supervisor_started',pid=os.getpid(),creation_filetime=supervisor_identity['creation_filetime'])
        while True:
            now=time.monotonic();attempts=[v for v in attempts if 0<=now-v<300]
            try:
                replies=tls(config,context);healthy=all(v['verified'] for v in replies.values())
                try:pid=int((PRIVATE/'broker.pid').read_text());process=process_identity(pid)
                # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
                except Exception:process={'state':'unknown'}
                image=process.get('image')
                if image and Path(image).resolve()!=Path(sys.executable).with_name('pythonw.exe').resolve():process=dict(process,state='unknown')
                receipts_clear=True
                try:policy.check_receipts(PRIVATE,uuid.uuid4().hex)
                # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
                except Exception:receipts_clear=False
                pending_clear=False;guest=None
                if not healthy and process['state']=='absent' and receipts_clear:
                    try:
                        guest=guest_status(config,'lab-stor-01');pending_clear=not guest['history_pending']
                    # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
                    except Exception:pass
                decision=choose(healthy,process['state'],port_state() if not healthy else 'occupied',receipts_clear,pending_clear,len(attempts)<3)
                if decision=='start_existing_controller':
                    # 原控制器死亡后可能留下-R子进程；只回收同一父PID且严格argv确认的通道。
                    for child in owned_tunnels(config,process['pid']):
                        log('orphan_tunnel_cleanup',**stop_verified_process(child))
                    attempts.append(now)
                    save(budget_file,{'schema':1,'boot_identity':boot,'attempt_monotonic':attempts})
                    # 控制器由常驻监督直接管理，不套一次性启动器再要求子进程逃离嵌套job。
                    # 当前用户会话仍是边界；不声称所有job/注销/宿主故障已覆盖。
                    error_log=(PRIVATE/'managed-controller.stderr.log').open('ab')
                    try:
                        # 【中文注释】启动具体命令/子进程；权限、目标和超时见参数，成功还要核对后置证据。
                        child=subprocess.Popen([str(Path(sys.executable).with_name('pythonw.exe')),str(PRIVATE/'workstation_fencing_broker.py'),str(PRIVATE)],
                            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=error_log,
                            creationflags=subprocess.CREATE_NO_WINDOW|subprocess.DETACHED_PROCESS)
                    # 【中文注释】无论成功或失败都处理本轮清理/释放；仍须遵守内部的目标与未决状态守卫。
                    finally:error_log.close()
                    log('controller_start_attempt',managed_pid=child.pid,attempts_in_300_seconds=len(attempts))
                if healthy and receipts_clear and now>=next_guest:
                    next_guest=now+30
                    results={}
                    for host in ('lab-stor-01','lab-stor-02'):
                        try:results[host]=guest_status(config,host,reprobe=True)
                        # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
                        except Exception as e:results[host]={'error_type':type(e).__name__}
                    guest=results;last_guest={'checked_local':datetime.datetime.now().isoformat(),'results':results}
                state={'updated_local':datetime.datetime.now().isoformat(),'updated_monotonic':time.monotonic(),
                       'supervisor_pid':os.getpid(),'host_boot_identity':boot,'decision':decision,'controller_process':process,'tls':replies,
                       'durable_receipts_clear':receipts_clear,'restart_attempts_in_300_seconds':len(attempts),'guest_checks':guest,'last_guest_checks':last_guest,
                       'supervisor_requested_vm_power_actions':[]}
                save(PRIVATE/'supervisor-state.json',state)
                if decision!=old_state:log('state_changed',decision=decision,pid=process.get('pid'));old_state=decision
            # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
            except Exception as e:log('cycle_failed',error_type=type(e).__name__)
            time.sleep(5)
    # 【中文注释】无论成功或失败都处理本轮清理/释放；仍须遵守内部的目标与未决状态守卫。
    finally:
        lock.seek(0);msvcrt.locking(lock.fileno(),msvcrt.LK_UNLCK,1);lock.close()

# 【中文注释】脚本执行入口；只有本分支受main判断保护，前面的顶层语句仍可能在导入时执行。
if __name__=='__main__':main()
