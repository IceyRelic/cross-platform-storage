# 配置来源与应用门槛

DRBD/Pacemaker源自48集成阶段静态配置，61策略需配套；不是可直接替换实时CIB的完整导出。Corosync/Samba/NFS/rsync来自00相应冻结模板；保留Samba finance1只读例外。两端metadata布局不同按原文件展示，必须按自己的实际卷核对。

Prometheus本地模板原9个exporter目标＋本身=10，41告警。私人remote_write整段移除；告警仅保留企业微信私有配置结构，不携带旧邮件/云账号。这里的占位字段不是部署成功证明。

systemd安装路径/Drop-in和Python版本见deployment；scripts backup代号/历史/stop/LUN取最终冻结，源push/manifest与逻辑MD5依相应snapshot版本。不能把混合来源误称同期全套新版本。
