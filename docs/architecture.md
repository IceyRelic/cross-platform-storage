# 架构

~~~mermaid
flowchart TD
    WIN[Windows SMB客户端] --> VIP[存储VIP]
    LIN[Linux NFS与iSCSI客户端] --> VIP
    VIP --> A[stor-svc-01]
    VIP --> B[stor-svc-02]
    A <--> D[4组DRBD同步复制]
    D <--> B
    P[Pacemaker与Corosync] --> A
    P --> B
    P --> F[Linux隔离代理]
    F --> W[宿主TLS broker与原生电源查询]
    W --> A
    W --> B
    A --> BK[rsync与备份代号]
    B --> BK
    BK --> H[backup-01：受保护历史与恢复]
    M[monitor-01：Prometheus/Alertmanager] --> Q[受限Squid出口]
    Q --> WX[企业微信]
~~~

| 角色 | 发布示例地址 | 用途 |
|---|---|---|
| stor-svc-01 / 02 | 192.0.2.10 / 20 | 双存储节点及四DRBD资源 |
| backup-01 | 192.0.2.30 | 三共享与普通文件LUN保护/恢复 |
| monitor-01 | 192.0.2.40 | 本地指标、41规则、通知 |
| client-linux-01 | 192.0.2.50 | NFS/iSCSI与恢复守卫 |
| VIP | 192.0.2.100 | 对外接入 |
| 云节点 | 自行填写 | Squid受限告警公网出口 |

五VM加一个出口云节点不等于六节点数据存储集群。VIP/文件系统/协议由集群资源控制，不能绕过集群手动制造两端可写。

DRBD design/dev/finance/lun01分别对应独立卷。保留已归档的节点metadata差异；不能把示例meta-disk internal或独立LV套到已格式化真实设备上。iSCSI导出的是LUN块设备，普通文件实验客户端只能由一个已确认写者管理其文件系统。

版本以冻结档案为准：CentOS7/Pacemaker1.1.23/DRBD9系列、Windows Workstation、旧Python2.7 helper及Windows Python3；rsync3.5.1独立路径不替换系统rsync。没有新版迁移/全新重建验收。
