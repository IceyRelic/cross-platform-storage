# cross-platform-storage

双节点跨平台存储实训：DRBD/Pacemaker、SMB/NFS/iSCSI、元数据保留备份与独立恢复、Prometheus告警，以及VMware Workstation实验隔离控制。

## 先看什么

- [架构与适用环境](docs/architecture.md)
- [部署顺序与参数准备](docs/deployment.md)
- [隔离与脑裂边界](docs/failover-and-fencing.md)
- [备份/恢复与元数据](docs/backup-and-restore.md)
- [实测结果定义](docs/validation.md)
- [排障案例](docs/troubleshooting.md)
- [限制](docs/limitations.md)和[来源/归属](docs/attribution.md)

## 已有证据支持的结果

| 范围 | 2026年9–10月实训结果 | 边界 |
|---|---|---|
| 架构 | 2存储节点、4DRBD资源、3协议；独立备份/监控/Linux客户端 | 云服务器仅告警出口，不是六节点存储集群 |
| 两方向自动隔离接管 | 阶段52正向70、53反向214个ACK文件独立重开后SHA匹配，共284 | 两轮合计；不是全盘/所有写中数据零丢失 |
| 共享历史 | design/dev/finance各7有效版本，自然轮换及正常备机重启后保全 | 不扩为LUN自然7版；LUN当时6版 |
| 独立恢复 | 三共享33文件/44对象内容与权限/ACL/xattr/属主/硬链接等对比通过 | 当前小样本；不是海量生产/数据库恢复 |
| 同期稳定性 | 30分钟三协议累计39630轮4MiB写入/刷新/回读校验，0校验错误 | 文件反复覆盖、小于缓存；NFS曾约5.154秒停顿 |
| 监控 | 历史结束快照10目标up、41告警规则 | 不代表全年SLA或所有告警实际收件 |
| LUN保护 | 精确设备/会话绑定、容量/inode准入及受限ENOSPC实验；普通文件备份/恢复 | 正式LUN当时无业务文件，真实包仅1目录对象 |

数据与测试条件见[validation](docs/validation.md)与[summary.json](results/summary.json)。不写99.9%、统一RTO、MTTD/MTTI或可归因性能提升百分比。

## 内容

- configs/：两节点DRBD、静态Pacemaker配置示例、Corosync/NFS/Samba/rsync/本地Prometheus/告警、systemd和SELinux策略。
- scripts/backup/：最终冻结的代号/后续联动、历史、逻辑MD5、普通文件LUN helper及源端两阶段同步。
- scripts/fencing/：Windows broker/身份库/监督，Linux代理；保留TLS、节点身份、nonce/期限、原生off确认及持久未决拒绝。
- scripts/storage/：只针对普通文件夹具的NFS显式安全重开示例。
- examples/：缺少私有值即不可用的参数模板；不含令牌、证书私钥或VM实际路径。

## 版本与复现范围

此包从截至2026-10-05第63阶段冻结材料整理；Windows Python3与CentOS旧Python2.7混合环境，rsync3.5.1独立安装。脚本有中文关键注释。

公开包做了示例地址/身份/路径转换、拒绝Python优化模式及监督源SHA更新，**没有按公共参数重新部署或重新测试**。不是从零一键安装包，不会提供自动覆盖磁盘/强制升主脚本。实际操作必须先读部署/隔离/恢复说明。

## 当前与历史状态

历史实测不能当现在在线保证。2026-10-06新开机观察中，存储01在等待对端、02地址尚未核实；此事件仍在单独排查，没有把它标为恢复成功。存储与K8s旧实验地址重叠，不能同时启用同地址节点。

## 贡献归属

个人原部署由本人确认；2026年9–10月的优化、排障、测量和本包整理有Codex辅助，未倒写原实训时期的独立成果。第三方DRBD/OCF/组件源码不改为本人原创；本包不包含其vendor实现、私有业务数据或整份培训材料，暂无整仓许可证授予。
