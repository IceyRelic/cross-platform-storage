# 2026-10-06冷启动恢复复盘

这是实际私有原环境的辅助恢复，公开版参数化代码仍未重新部署/执行；原63阶段数据与此次观察分开。

## 根因链

备用网卡ens33存在/驱动正常，但NetworkManager服务active、联网控制disabled；持久状态NetworkingEnabled=false。原ifcfg静态地址/ONBOOT=yes已经正确，所以开机仍无IP。

备用DRBD报本机IP缺失退出20，Corosync无interface退出，Pacemaker依赖失败。主节点的旧drbd.service无限等待peer，Before/After排序让Pacemaker排队。宿主监督仍存活、原控制器已退出；监督无法查询未运行CIB的未决隔离，因此拒绝启动控制器。

## 实际恢复顺序

1. 排除同地址K8s节点：普通关机超时后经本人单独确认关闭正确VM。没有据此推定它设置了NM联网false，更不当作存储fencing演练。
2. 本人控制台临时启用网卡/地址获得SSH，助手核对身份与原配置。以下地址是示例：

~~~bash
ip link set dev ens33 up
ip addr add 192.0.2.20/24 dev ens33
~~~

3. root私有备份状态文件/ifcfg与原SHA，唯一实际联网修复：

~~~bash
nmcli networking on
~~~

原连接自动激活，状态true、autoconnect=yes，新SSH复核；ifcfg字节没有改。没有实际再reboot证明，也不直接编辑NM状态文件绕过管理接口。联网关闭来源未归因。

4. 控制器启动前明确证明：两端Pacemaker inactive、没有Primary/open DRBD或业务挂载；两个VM原生身份/路径吻合、on；旧控制器确实不存在、端口自由、历史回执无未决、原源码SHA吻合。然后人工启动原受限控制器，TLS和两端实际agent monitor通过。没有清回执、降低未知状态拒绝或执行新的VM off。
5. 备用普通启动Corosync，恢复2成员/quorum；再提交已有DRBD/Pacemaker：

~~~bash
systemctl start corosync
systemctl start --no-block drbd
systemctl start --no-block pacemaker
~~~

no-block仅提交作业。直到后续观察两端UpToDate/UpToDate、全部Master和业务归主01、无Failed Actions才记恢复。不强制primary/丢弃副本/修改quorum/fencing，旧依赖架构未重排。

6. 原LUN timer自然重试上传/发布/确认。源任务先前在未就绪期间跳过而下次周期较晚，核对当前单写主/四复制/实际挂载后只补一次原任务：

~~~bash
systemctl start source-manifest.service
systemctl start push-backup.service
~~~

备端原timer自然后续同代MD5/历史完成；不更改timer/保留策略，不制造新业务文件或做故障注入。

## 22:34观察

- 2节点在线/quorum，4组UpToDate/UpToDate；业务角色均主01，隔离保持。
- Linux NFS挂载/iSCSI会话/ready恢复；SMB服务started，未本轮复测Windows应用。
- 10监控目标up、41规则、无活动告警；自然消息实际收件未重新确认，不计算MTTD。
- 三共享新源代号与后续/MD5同代通过、历史数7；LUN新上传/发布/确认回执一致。
- nfs-notify仍为原disabled例外，旧network.service失败标记不等于当前NM不连接。

## 边界与记录更正

没有新全盘哈希、实际再reboot、全部协议应用或全部生命周期证明。旧单节点init无限等待/监督冷启动人工介入等依赖边界保留，不能说永久修复所有场景。

原驱动第一轮有Python2 UTF8解析失败，在服务动作前拒绝；修正后才实际提交。初期固定名只读诊断被后次覆盖，第一条ARP不完整结论来自工具输出/检查点，未伪造原件SHA；后改微秒名。本地档案保留原/新代码、流程与逐结论来源，公共包不带私有CIB/回执/账号/原图。
