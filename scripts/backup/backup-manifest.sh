#!/bin/bash
# 【中文注释】用途：备份端生成清单/代号标记；仅有清单文件不等同内容和受保护历史验证成功。
# 【中文注释】原版/许可证/脚本体保留；本文件为阅读副本，不替换已验证运行文件。
# 【中文注释】逐段流程、调用及原行号见旁边的“逐段解读”；续行/引号/HereDoc内部保持原样。
set -euo pipefail

DATE=$(date +%F_%H-%M-%S)
BASE=/backup
OUTDIR=/backup/checksums
METRIC_DIR=/var/lib/node_exporter/textfile_collector
OUT="${METRIC_DIR}/backup_manifest.prom"
TMP="${OUT}.$$"

mkdir -p "$OUTDIR" "$METRIC_DIR"
: > "$TMP"

gen_md5() {
    NAME=$1
    SRC=$2
    OUTFILE="${OUTDIR}/${NAME}_${DATE}.md5"

    if [ -d "$SRC" ]; then
        (
            cd "$SRC"
            find . -type f -print0 | /usr/local/bin/logical-md5-manifest.py | sort
        ) > "$OUTFILE"

        FILE_COUNT=$(wc -l < "$OUTFILE")

        echo "backup_manifest_status{name=\"${NAME}\"} 1" >> "$TMP"
        echo "backup_manifest_timestamp{name=\"${NAME}\"} $(date +%s)" >> "$TMP"
        echo "backup_manifest_file_count{name=\"${NAME}\"} ${FILE_COUNT}" >> "$TMP"
    else
        echo "backup_manifest_status{name=\"${NAME}\"} 0" >> "$TMP"
        echo "backup_manifest_timestamp{name=\"${NAME}\"} $(date +%s)" >> "$TMP"
        echo "backup_manifest_file_count{name=\"${NAME}\"} 0" >> "$TMP"
    fi
}
gen_md5_dev() {
    NAME=dev
    SRC=/backup/dev/current
    OUTFILE="${OUTDIR}/${NAME}_${DATE}.md5"

    if [ -d "$SRC" ]; then
        (
            cd "$SRC"
            find . -type f \
                ! -path "./nfsinfo/*" \
                ! -name ".rmtab*" \
                ! -name ".etab*" \
                ! -name ".xtab*" \
                -print0 | /usr/local/bin/logical-md5-manifest.py | sort
        ) > "$OUTFILE"

        FILE_COUNT=$(wc -l < "$OUTFILE")

        echo "backup_manifest_status{name=\"${NAME}\"} 1" >> "$TMP"
        echo "backup_manifest_timestamp{name=\"${NAME}\"} $(date +%s)" >> "$TMP"
        echo "backup_manifest_file_count{name=\"${NAME}\"} ${FILE_COUNT}" >> "$TMP"
    else
        echo "backup_manifest_status{name=\"${NAME}\"} 0" >> "$TMP"
        echo "backup_manifest_timestamp{name=\"${NAME}\"} $(date +%s)" >> "$TMP"
        echo "backup_manifest_file_count{name=\"${NAME}\"} 0" >> "$TMP"
    fi
}

gen_md5 design  /backup/design/current
gen_md5 finance /backup/finance/current
gen_md5_dev

python /usr/local/bin/backup-generation.py mark "$OUTDIR" "$DATE"
mv -f "$TMP" "$OUT"
