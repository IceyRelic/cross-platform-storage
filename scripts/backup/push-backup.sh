#!/bin/bash
# 【中文注释】用途：源端三共享复制；由VIP/挂载守卫、单任务状态、清单同步和退出码判定本轮结果。
# 【中文注释】原版/许可证/脚本体保留；本文件为阅读副本，不替换已验证运行文件。
# 【中文注释】逐段流程、调用及原行号见旁边的“逐段解读”；续行/引号/HereDoc内部保持原样。

# Data/xattr first, then ACL: retain fake-super ACLs across repeated copies.
rsync_metadata() {
    local task_arg
    local -a task_acl_args=()
    for task_arg in "$@"; do
        if [[ "$task_arg" != "--delete" ]]; then task_acl_args+=("$task_arg"); fi
    done
    /opt/codex-rsync-3.5.1/bin/rsync -aHXS --numeric-ids \
        --filter='-x system.*' \
        --filter='-x security.selinux' \
        --filter='-x trusted.SGI_ACL_FILE' \
        --filter='-x trusted.SGI_ACL_DEFAULT' \
        --filter='-x user.rsync.%*' "$@" || return "$?"
    /opt/codex-rsync-3.5.1/bin/rsync -aHA --numeric-ids "${task_acl_args[@]}"
}

set -euo pipefail

VIP="192.0.2.100"
BACKUP_IP="192.0.2.30"
PASSFILE="/etc/rsync.pass"
LOGDIR="/var/log/storage-backup"
METRIC_DIR="/var/lib/node_exporter/textfile_collector"
OUT="${METRIC_DIR}/backup_jobs.prom"
TMP="${OUT}.$$"
LOCKFILE="/var/run/storage_backup.lock"

mkdir -p "$LOGDIR" "$METRIC_DIR"

exec 9>"$LOCKFILE"
flock -n 9 || exit 0

# 非 VIP 节点：清理旧指标，避免暴露陈旧数据
if ! ip -4 -o addr show | awk '{print $4}' | cut -d/ -f1 | grep -Fxq "$VIP"; then
    rm -f "$OUT" "$TMP"
    exit 0
fi

DATE=$(date +%F_%H-%M-%S)
NOW=$(date +%s)

# Publish a failure marker if an unexpected early error interrupts this run.
: > "$TMP"
trap 'if [[ -f "$TMP" ]]; then echo "backup_pipeline_status 0" >> "$TMP"; mv -f "$TMP" "$OUT"; fi' EXIT
printf 'backup_runner_active 1\nbackup_pipeline_status 2\nbackup_pipeline_started_timestamp %s\n' "$NOW" > "$TMP"
mv -f "$TMP" "$OUT"
: > "$TMP"
echo "backup_runner_active 1" >> "$TMP"
FAILED=0
# Refuse to mirror an unmounted local directory into the remote backup.
for ROLE_ID in design:0 dev:1 finance:2; do
    ROLE=${ROLE_ID%:*}
    MINOR=${ROLE_ID#*:}
    read -r MOUNT_TARGET MOUNT_SOURCE MOUNT_TYPE <<< "$(findmnt -rn -o TARGET,SOURCE,FSTYPE -T "/data/$ROLE")"
    [[ "$MOUNT_TARGET" == "/data/$ROLE" && "$MOUNT_SOURCE" == "/dev/drbd${MINOR}" && "$MOUNT_TYPE" == "xfs" ]] || exit 1
done
bash /usr/local/bin/source-manifest.sh

backup_one() {
    local NAME=$1
    local SRC=$2
    local MODULE=$3
    shift 3

    local LOGFILE="${LOGDIR}/${NAME}_${DATE}.log"
    local -a cmd=(rsync_metadata --delete)

    if [ "$#" -gt 0 ]; then
        cmd+=("$@")
    fi

    cmd+=("$SRC" "rsync://backupuser@${BACKUP_IP}/${MODULE}/" "--password-file=$PASSFILE")

    if "${cmd[@]}" >"$LOGFILE" 2>&1; then
        echo "backup_job_status{name=\"${NAME}\"} 1" >> "$TMP"
        echo "backup_job_timestamp{name=\"${NAME}\"} ${NOW}" >> "$TMP"
        echo "backup_last_success_timestamp{name=\"${NAME}\"} ${NOW}" >> "$TMP"
    else
        FAILED=1
        echo "backup_job_status{name=\"${NAME}\"} 0" >> "$TMP"
        echo "backup_job_timestamp{name=\"${NAME}\"} ${NOW}" >> "$TMP"
    fi
}

backup_one design  /data/design/   design
backup_one dev     /data/dev/      dev \
    --no-devices --no-specials \
    --exclude='nfsinfo/rpc_pipefs/**' \
    --exclude='nfsinfo/nfsdcltrack/**' \
    --exclude='nfsinfo/v4recovery/**' \
    --exclude='**/.rmtab*' \
    --exclude='**/.etab*' \
    --exclude='**/.xtab*'
backup_one finance /data/finance/  finance
# Commit a generation only after all business copies completed.
GENERATION=0
if [[ "$FAILED" -eq 0 ]]; then
    GENERATION=$(python /usr/local/bin/backup-generation.py create /data/.checksums)
fi
# Sync the manifests and their completion certificate.
if rsync -a --no-owner --no-group /data/.checksums/ \
    rsync://backupuser@${BACKUP_IP}/checksums/ \
    --password-file="$PASSFILE"; then

    echo "backup_checksums_sync 1" >> "$TMP"
    if [[ "$FAILED" -eq 0 ]]; then
        echo "backup_pipeline_generation{node=\"$(hostname -s)\"} ${GENERATION}" >> "$TMP"
        echo "backup_pipeline_completed_timestamp $(date +%s)" >> "$TMP"
    fi
else
    echo "backup_checksums_sync 0" >> "$TMP"
    FAILED=1
fi
echo "backup_pipeline_status $((1-FAILED))" >> "$TMP"
mv -f "$TMP" "$OUT"
exit "$FAILED"
