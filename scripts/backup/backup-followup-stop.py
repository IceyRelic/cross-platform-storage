#!/usr/bin/python
# -*- coding: utf-8 -*-
# 【中文注释】用途：备份后续联动的运行/历史版本：稳定证书、同代校验、串行任务和指标发布。
# 【中文注释】阅读副本：原版与原SHA保留；依赖源码哈希/AST抽取的驱动应执行验证过的原版。
# 【中文注释】顺序：先看常量/配置 → 关键函数 → 顶层或main入口 → 异常与清理。
# 【中文注释】历史版本能力按函数体/所属阶段判定，不能把新增守卫倒写到旧版。
"""systemd 219停止后补记非正常退出；SIGKILL无法被主Python捕获，不能留下陈旧进行中指标。"""
from __future__ import print_function
# 发布版保留assert身份/准入守卫，拒绝-O/-OO以免移除这些条件。
if not __debug__:
    raise RuntimeError('Optimized Python disables safety guards; refused')
import fcntl,imp,json,os,stat,subprocess,time

# 【中文注释】函数 properties：处理此命名步骤的参数与返回值；具体边界/异常按下方函数体及所属阶段核对。
def properties():
    # 【中文注释】启动具体命令/子进程；权限、目标和超时见参数，成功还要核对后置证据。
    p=subprocess.Popen(['systemctl','show','backup-followup.service','-p','Result','-p','ExecMainCode','-p','ExecMainStatus'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    text,error=p.communicate();assert p.returncode==0
    return dict(line.split('=',1) for line in text.splitlines() if '=' in line)

# 【中文注释】函数 failed：把遍历等底层错误继续抛出，避免对象缺失却返回不完整的成功视图。
def failed(values):
    """同时核对原生退出方式和状态；管理员中途停止也不能保留成功/进行中。"""
    assert set(values)==set(('Result','ExecMainCode','ExecMainStatus'))
    return not (values['Result']=='success' and values['ExecMainCode']=='1' and values['ExecMainStatus']=='0')

# 【中文注释】函数 main：程序入口：解析参数/标准输入并按分支执行；导入安全性仍取决于模块顶层代码。
def main():
    assert os.geteuid()==0
    native=properties()
    if not failed(native):
        print(json.dumps({'status':'normal_exit_metric_preserved','native':native}));return
    F=imp.load_source('stop_followup','/usr/local/sbin/backup-followup.py')
    G=imp.load_source('stop_generation','/usr/local/bin/backup-generation.py');F.G=G
    # 【中文注释】身份/路径/权限守卫：只允许本轮授权对象，阻止链接、替换或跨目录操作。
    assert os.path.realpath(F.STATE)==F.STATE
    s=os.stat(F.STATE);assert s.st_uid==0 and stat.S_IMODE(s.st_mode)==0700
    fd=os.open(F.STATE+'/followup.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0600)
    with os.fdopen(fd,'r+') as lock:
        # 【中文注释】身份/路径/权限守卫：只允许本轮授权对象，阻止链接、替换或跨目录操作。
        assert stat.S_ISREG(os.fstat(fd).st_mode) and os.fstat(fd).st_uid==0
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
        except IOError:
            # 外部手工运行持锁时拒绝覆盖其指标；该路径只记日志，不能称故障补记完成。
            print(json.dumps({'status':'lock_busy_no_metric_overwrite','native':native}));return
        state=G.load(F.STATE+'/state.json')
        assert native==properties(),'Unit exit changed; refuse stale metric write'
        F.publish(0,state)
        record={'checked_timestamp':int(time.time()),'native':native,'completed_generation_preserved':state.get('completed_generation',0),'last_success_preserved':state.get('last_success_timestamp',0)}
        G.save(F.STATE+'/last-native-failure.json',record)
        print(json.dumps({'status':'native_abnormal_exit_marked_failed','native':native}))

# 【中文注释】脚本执行入口；只有本分支受main判断保护，前面的顶层语句仍可能在导入时执行。
if __name__=='__main__':main()
