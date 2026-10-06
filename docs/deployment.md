# 部署顺序与私有参数

## 这是模板，先准备隔离环境

发布示例为192.0.2.*；替换网段/主机名/设备/LV/IQN/UUID必须一并核对。原实验与K8s复用地址，不同时启动重复地址VM。当前公开脚本未按新参数部署，不在已有真实数据设备上整包执行。

1. 准备两存储、备份、监控、客户端VM和Windows宿主工具；核对每台BIOS UUID/MAC/VMX与来宾身份。
2. 按实际拓扑准备空白实验盘/LV、匹配内核的DRBD模块、Pacemaker/Corosync和协议组件。DRBD/OCF官方软件由合法来源安装，本库不打包vendor代码。
3. 审阅configs/drbd两节点资源，核对元数据布局，配置Corosync；保持no-quorum-policy=stop和STONITH，不用旧ignore/禁隔离方案绕过问题。
4. 先建立可信隔离通道/私有身份及受限TLS，验证可查询正确目标和拒绝未配置对象；不能因为缺控制通道就跳过隔离。
5. 合并静态Pacemaker资源/约束示例，核对DRBD标准fence/unfence脚本来源；配置61阶段SELinux最小connectto策略，保持enforcing。不要直接replace历史完整CIB。
6. 配置NFS/Samba/iSCSI。iSCSI用自己的目标IQN、门户、TPGT/LUN0、客户端ACL和需要的认证；本库不导出targetcli含CHAP的完整配置。
7. rsync3.5.1在/opt/codex-rsync-3.5.1；源/备元数据及fake-super策略按backup文档，部署核心脚本到对应安装路径，再配置systemd。
8. 指标/告警先核对本地Prometheus和41规则。告警账户只填私有配置；公开版去掉了历史私人remote_write，未宣称云托管仍在线。

## Python与安装路径

Linux脚本依原CentOS的Python2.7语法/urllib2/imp；Windows三个隔离脚本用Python3。不要为发布外观直接升级语法再宣称原环境通过。脚本主动拒绝-O/-OO，以免身份/准入assert失效。

备端/usr/local/bin：backup-generation.py、backup-history.py、logical-md5-manifest.py、backup-manifest.sh、verification.sh。

备端/usr/local/sbin：backup-followup.py、backup-followup-stop.py、lun01-file-backup.py。客户端同LUN helper装到/usr/local/sbin。源端push-backup.sh/source-manifest.sh和backup-generation.py需按原unit引用安装；路径可改变，但所有调用者/指标/配置必须一起对齐。

60-interruption-status.conf是backup-followup.service的drop-in，安装到backup-followup.service.d/；不是另一个可独立启动的服务。OnBoot/后续观察是原timer相对启动周期，不当作固定每天时刻。LUN捕获/自然轮换和三共享历史分开。

## 隔离私有目录

Windows使用本人受限目录Documents/CodexStorageFencingRuntime，放broker-config.json、channel-cert.pem/channel-key.pem及三个脚本。监督读取的broker SHA已按本公共文件LF字节更新；再改broker必须审核并同步SHA，不能删掉检查。

verify_vmware_identity.py要求环境STORAGE_VM_ROOT（真实VM根目录）及STORAGE_LOCAL_EVIDENCE_DIR（自己的私有记录目录）。缺参数会拒绝导入；不默认指向本人VM。

Linux/etc/codex-storage-power-channel：root目录0700、credential.json0600、受控CA证书；credential示例只有占位值。fence_workstation_lab里的两节点UUID/MAC占位必须按独立身份核对后填写，并与broker mapping完全一致；检查逻辑保留，错误身份不应变成功。

reverse SSH经已核对known_hosts把来宾127.0.0.1:9447转到宿主127.0.0.1:8767；broker不暴露公网。令牌64字符且各调用者独立，TLS私钥不进入Git。源码路径与VMCLI/VMRUN安装位置需要核对，不能因文件存在就推断off。

## systemd与验证

先语法/版本/配置审阅，再在自己的隔离环境按原依赖链逐项启用，不批量systemctl start。本次没有执行公开版自检或项目测试；已有源码自检保留，但不能拿模型通过冒充实际隔离。

configs/systemd是选定运行样例，备份配置缺少私有密码文件会失败；任何覆盖导入、数据丢弃、强制升主或电源off需对具体目标/权威副本另做决定。
