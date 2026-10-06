#!/bin/sh
# 只读：在正确的存储VM上使用，不能在地址重叠的K8s环境误执行。
set -eu
hostname
pcs status
drbdadm status
findmnt -rn -t nfs,nfs4,xfs
systemctl is-active corosync pacemaker
