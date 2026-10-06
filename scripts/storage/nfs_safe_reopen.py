# -*- coding: utf-8 -*-
"""普通文件示例的显式恢复：原FD先关闭，新开并获取整文件锁，再校验身份/版本，拒绝冲突。

只允许本轮私有fixture；适用于遵守同一POSIX锁约定的客户端。不是服务器透明锁修复/事务数据库。
NFS hard syscall可能阻塞；预算只控制操作准入/检查点，不声称能强制中断内核I/O。
"""
# 发布版保留assert身份/准入守卫，拒绝-O/-OO以免移除这些条件。
if not __debug__:
    raise RuntimeError('Optimized Python disables safety guards; refused')
import errno,fcntl,hashlib,os,re,stat,subprocess,time

class Refusal(Exception):
    def __init__(self,code):self.code=code

def sha(data):return hashlib.sha256(data).hexdigest()

def check_root(root,use_nfs):
    """限制私有目录且拒绝符号链接；模型只允许/var/tmp，运行只允许现有NFS挂载下fixture。"""
    prefix='/mnt/devshare/project' if use_nfs else '/var/tmp'
    assert os.path.dirname(root)==prefix and re.match(r'^\.codex_nfs_recover_[0-9a-f]{16}$',os.path.basename(root))
    if os.path.realpath(root)!=root:raise Refusal('root_identity_refused')
    st=os.lstat(root)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.getuid():raise Refusal('root_identity_refused')
    if use_nfs:
        p=subprocess.Popen(['findmnt','-rn','-o','TARGET,SOURCE,FSTYPE,OPTIONS','-T',root],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        a,b=p.communicate()
        if p.returncode or not a.startswith('/mnt/devshare 192.0.2.100:/ nfs4 ') or 'hard' not in a or 'local_lock=none' not in a:raise Refusal('mount_identity_refused')

def identity(fd):
    """inode/UID/文件类型/链接数/大小都必须匹配；不只凭名字或相同内容。"""
    s=os.fstat(fd)
    return {'inode':s.st_ino,'uid':s.st_uid,'bytes':s.st_size,'nlink':s.st_nlink,'regular':stat.S_ISREG(s.st_mode)}

def read_all(fd,size):
    """有界读取同一个已加锁FD；不另外打开同inode后关闭，以免POSIX锁被隐式释放。"""
    os.lseek(fd,0,os.SEEK_SET);chunks=[];left=size+1
    while left:
        block=os.read(fd,min(left,65536))
        if not block:break
        chunks.append(block);left-=len(block)
    data=b''.join(chunks)
    if len(data)!=size:raise Refusal('size_changed_no_write')
    return data

class Handle(object):
    """仅在新锁仍持有、身份及版本再次一致时写；不确定写入状态禁止自动重复提交。"""
    def __init__(self,fd,path,wanted,before,after,offset,patch,state):
        self.fd=fd;self.path=path;self.wanted=wanted;self.before=before;self.after=after
        self.offset=offset;self.patch=patch;self.state=state

    def commit(self):
        if self.state=='uncertain':return {'status':'write_uncertain_do_not_retry','bytes_written':None}
        if self.state=='refused':return {'status':'previous_refusal_reopen_required','bytes_written':0}
        assert self.fd is not None
        try:
            if identity(self.fd)!=self.wanted or os.lstat(self.path).st_ino!=self.wanted['inode']:
                self.state='refused';return {'status':'identity_changed_no_write','bytes_written':0}
            current=read_all(self.fd,len(self.before))
        except Exception as e:
            self.state='refused';return {'status':'prewrite_io_refused_reopen_required','bytes_written':0,'errno':getattr(e,'errno',None)}
        if current==self.after:
            try:os.fsync(self.fd)
            except Exception as e:
                self.state='uncertain';return {'status':'write_uncertain_do_not_retry','bytes_written':0,'errno':getattr(e,'errno',None)}
            self.state='already_applied';return {'status':'already_applied_no_write','bytes_written':0,'sha256':sha(current)}
        if current!=self.before:
            self.state='refused';return {'status':'content_conflict_no_write','bytes_written':0,'observed_sha256':sha(current)}
        self.state='uncertain'  # 先标记，再写；异常/部分写不能自动重放。
        try:
            os.lseek(self.fd,self.offset,os.SEEK_SET);written=os.write(self.fd,self.patch)
            if written!=len(self.patch):raise IOError(errno.EIO,'Partial test write')
            os.fsync(self.fd)
            if read_all(self.fd,len(self.after))!=self.after:raise IOError(errno.EIO,'Post-write mismatch')
            self.state='committed'
            return {'status':'committed_fsync_readback','bytes_written':written,'sha256':sha(self.after)}
        except Exception as e:
            return {'status':'write_uncertain_do_not_retry','bytes_written':None,'errno':getattr(e,'errno',None)}

    def close(self):
        if self.fd is None:return {'fd_already_closed':True}
        fd=self.fd;self.fd=None;out={}
        try:fcntl.lockf(fd,fcntl.LOCK_UN,0,0,os.SEEK_SET);out['unlock_completed']=True
        except IOError as e:out['unlock_errno']=e.errno
        try:os.close(fd);out['close_completed']=True
        except OSError as e:out['close_errno']=e.errno
        return out

def prepare(root,name,wanted,before,offset,patch,use_nfs=True,budget=15):
    """一次非阻塞加锁尝试；锁忙/版本冲突/身份变化均不写，成功返回持锁handle供独立验证。"""
    assert re.match(r'^record-[0-9]{6}\.bin$',name)
    assert len(before)==65536 and len(patch)==16 and 0<=offset<=len(before)-16 and budget>0
    started=float(open('/proc/uptime').read().split()[0]);fd=None
    def admitted():
        if float(open('/proc/uptime').read().split()[0])-started>budget:raise Refusal('budget_exceeded_no_write')
    try:
        check_root(root,use_nfs);admitted();path=root+'/'+name
        old=os.lstat(path)
        if not stat.S_ISREG(old.st_mode):raise Refusal('nonregular_or_symlink_no_write')
        fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
        if identity(fd)!=wanted:raise Refusal('identity_changed_no_write')
        admitted()
        try:fcntl.lockf(fd,fcntl.LOCK_EX|fcntl.LOCK_NB,0,0,os.SEEK_SET)
        except IOError as e:
            if e.errno in (errno.EAGAIN,errno.EACCES):raise Refusal('lock_busy_no_write')
            raise
        admitted();current=read_all(fd,len(before));after=before[:offset]+patch+before[offset+len(patch):]
        if current not in (before,after):raise Refusal('content_conflict_no_write')
        admitted();state='already_applied' if current==after else 'ready'
        handle=Handle(fd,path,wanted,before,after,offset,patch,state);fd=None
        return {'status':'already_applied_locked' if state=='already_applied' else 'reopened_locked_version_verified',
                'before_sha256':sha(before),'after_sha256':sha(after),'bytes_written':0},handle
    except Refusal as e:return {'status':e.code,'bytes_written':0},None
    except Exception as e:return {'status':'io_or_validation_refused_no_write','bytes_written':0,'errno':getattr(e,'errno',None)},None
    finally:
        if fd is not None:os.close(fd)  # 同一文件在此进程只有该恢复FD，关闭也释放未保留的锁。
