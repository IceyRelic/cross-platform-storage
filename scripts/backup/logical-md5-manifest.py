#!/usr/bin/python
# -*- coding: utf-8 -*-
# 【中文注释】用途：运行版逻辑普通文件筛选和MD5清单入口，支持fake-super对象识别。
# 【中文注释】阅读副本：原版与原SHA保留；依赖源码哈希/AST抽取的驱动应执行验证过的原版。
# 【中文注释】顺序：先看常量/配置 → 关键函数 → 顶层或main入口 → 异常与清理。
# 【中文注释】历史版本能力按函数体/所属阶段判定，不能把新增守卫倒写到旧版。
from __future__ import print_function
# 发布版保留assert身份/准入守卫，拒绝-O/-OO以免移除这些条件。
if not __debug__:
    raise RuntimeError('Optimized Python disables safety guards; refused')
import os, re, stat, subprocess, sys

# 【中文注释】函数 regular_mode：解析对象类型信息，供逻辑普通文件判断使用。
def regular_mode(value):
    first=value.split(None,1)[0] if value else ''
    if not re.match(r'^[0-7]{5,7}$',first):
        raise ValueError('Invalid fake-super mode')
    return stat.S_ISREG(int(first,8))

# 【中文注释】函数 logical_regular：判断路径是否代表逻辑普通文件，包含fake-super对象类型判断。
def logical_regular(path):
    if not stat.S_ISREG(os.lstat(path).st_mode): return False
    env=os.environ.copy(); env['LC_ALL']='C'
    # 【中文注释】启动具体命令/子进程；权限、目标和超时见参数，成功还要核对后置证据。
    p=subprocess.Popen(['getfattr','--only-values','-n','user.rsync.%stat','--',path],
                       stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
    value,error=p.communicate()
    if p.returncode==0: return regular_mode(value)
    if b'No such attribute' in error: return True
    raise IOError('Cannot read logical file metadata')

# 【中文注释】函数 main：程序入口：解析参数/标准输入并按分支执行；导入安全性仍取决于模块顶层代码。
def main():
    if sys.argv[1:]==['--self-check']:
        assert regular_mode('100640 0,0 0:0')
        assert not regular_mode('120777 0,0 0:0')
        assert not regular_mode('060640 0,0 0:0')
        try: regular_mode('invalid')
        # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
        except ValueError: pass
        else: raise AssertionError('Invalid metadata accepted')
        print('SELF_CHECK=pass'); return
    if sys.argv[1:]: raise ValueError('Unexpected arguments')
    # ponytail: keep the filename list in memory; stream NUL records for large trees.
    data=sys.stdin.read()
    if data and not data.endswith('\0'): raise ValueError('Unterminated filename record')
    for path in data.split('\0'):
        if path and logical_regular(path):
            # Native md5sum preserves its filename escaping and output format.
            subprocess.check_call(['md5sum','--',path])

# 【中文注释】脚本执行入口；只有本分支受main判断保护，前面的顶层语句仍可能在导入时执行。
if __name__=='__main__':
    try: main()
    # 【中文注释】保留并处理这一类失败；是否重试/记录/返回非零由本分支定义，不应直接算成功。
    except Exception:
        sys.stderr.write('logical-md5-manifest: scan or metadata check failed\n')
        sys.exit(2)
