# 备份、历史与恢复

## 三共享流程

原-aH不足以保存ACL/xattr；单轮-aHAXS也不能简单保证重复副本的fake-super ACL。实际采用独立rsync3.5.1两阶段：内容/xattr/稀疏与硬链接先传，ACL后传，数值UID/GID保留；排除system/security.selinux/相关ACL及rsync保留属性的策略按源码，SELinux保持enforcing。

逻辑MD5依据普通文件或fake-super中的原逻辑类型，不能对恢复端原始表现随意find全部文件后声称相同。源挂载精确核对后生成证书；三共享MD5与代号匹配，后续manifest→verify→history串行，物理历史与ready状态相符才算completed，不刷新旧成功冒充新成功。

backup-followup-stop补记真实异常退出/中断指标。Timer Result=success不够，需任务代号、每共享状态、时间、实际恢复/历史。7历史版本排序不是文件名/墙钟排序；自然新版本/淘汰与正常备机reboot保全已验，写中崩溃/历史发布窗口仍有待验。

## 普通文件LUN

用途经本人选择为普通文件实验。精确挂载/文件系统UUID/块设备major:minor/sysfs/SID/IQN/门户/TPGT/LUN0在tar前后核对；旧历史与新source_binding版本兼容。预算包含512MiB余量和动态inode准入，暂存只按已核对对象定向清理，不是生产硬配额。

实际隔离文件系统容量/inode/ENOSPC实验与CLI恢复通过；正式LUN当时只有1目录对象、6个历史版，不写业务数据库一致性或自然7版轮换通过。tar/fsync/回执发布与中断守卫不等于任意应用快照。

## 恢复顺序

1. 先选明确历史版本与目标空目录，记录源/包SHA和设备身份。
2. 验证manifest/捕获顺序与对象边界；隔离还原，不覆盖在线共享或真实块盘。
3. 按路径/类型/内容/UID/GID/mode/ACL/xattr/硬链接逐对象核对；本次33文件44对象包含目录mtime对比。
4. 恢复权限和只读拒写真实检查分开；原历史/回执保留，不通过改全局权限“修复”测试。

不提供自动丢弃DRBD备用或覆盖生产目录的脚本。历史事故恢复有具体批准与保全，不能复制为通用定时动作。
