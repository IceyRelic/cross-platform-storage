# 隔离与脑裂边界

通信中断会破坏复制/集群可见性，但不等于每次通信中断必然脑裂。历史dev/design事件已保全备用、只读比较并分别获得主01权威重建批准；底层网络/宿主通信因果未完整确定。

后续自动隔离链：来宾代理认证TLS→peer挑战能力→caller/target/nonce/session/期限校验→两边角色与原生VM身份/状态核对→持久未决消费→单侧off→原生重复off确认。超时/未知状态不当成功、不改关另一侧；旧许可/重放/控制器失效拒绝。

Pacemaker启用STONITH/no-quorum stop，DRBD resource-and-stonith及标准fence/unfence hook配套。Windows监督只恢复已确认不存在的控制器实例，检查PID/创建时刻、独占端口、未决回执与启动域预算；不杀异常活进程、不把on当来宾未暂停。

## 已有演练

- 51复合失效：活跃主暂停＋管理不可用时备用未提升，保留失败首轮及修正。
- 52正向/53反向：已确认ACK文件70＋214，off接收前后顺序与唯一写主/新写ACK独立核对。
- 54/55补充原生NFS观测和双向有界接管；更多分区组合/长期生命周期未全验。
- 61 DRBD callback在drbd_t访问cluster_t IPC被SELinux拒绝；仅加Unix stream connectto，enforcing保持。

本库不复制LINBIT vendor hook实现，也不伪称只开fencing开关就能永远防脑裂。两VM共享一个宿主控制器，宿主失效、虚拟网络/调用者/电源确认等仍有边界，不是生产级BMC HA方案。

## 不完整配置必须拒绝

实际UUID/MAC/VMX、TLS证书与令牌私有填写；公开模板不具备实际电源许可。保留全部身份/期限/持久未决/版本校验。监督SHA因注释/公共参数变化重新绑定到公开broker文件，但这个新组合未部署/复测。
