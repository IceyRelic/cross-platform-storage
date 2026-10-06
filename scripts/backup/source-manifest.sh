#!/bin/bash
# 【中文注释】用途：生成源文件清单；具体逻辑文件筛选、排除范围和证书行为按该版本代码执行。
# 【中文注释】原版/许可证/脚本体保留；本文件为阅读副本，不替换已验证运行文件。
# 【中文注释】逐段流程、调用及原行号见旁边的“逐段解读”；续行/引号/HereDoc内部保持原样。
set -euo pipefail

BASE=/data
OUTDIR=/data/.checksums
METRIC_DIR=/var/lib/node_exporter/textfile_collector
OUT="${METRIC_DIR}/source_manifest.prom"
TMP="${OUT}.$$"

mkdir -p "$OUTDIR" "$METRIC_DIR"
: > "$TMP"

gen_md5() {
    NAME=$1
    SRC=$2
    OUTFILE="${OUTDIR}/${NAME}.md5"

    if [ -d "$SRC" ]; then
        (
            cd "$SRC"
            find . -type f -exec md5sum {} \; | sort
        ) > "$OUTFILE"

        echo "source_manifest_status{name=\"${NAME}\"} 1" >> "$TMP"
        echo "source_manifest_timestamp{name=\"${NAME}\"} $(date +%s)" >> "$TMP"
    else
        echo "source_manifest_status{name=\"${NAME}\"} 0" >> "$TMP"
    fi
}
gen_md5_dev() {
    SRC=/data/dev
    OUTFILE="${OUTDIR}/dev.md5"

    if [ -d "$SRC" ]; then
        (
            cd "$SRC"
            find . -type f \
                ! -path "./nfsinfo/*" \
                ! -name ".rmtab*" \
                ! -name ".etab*" \
                ! -name ".xtab*" \
                -exec md5sum {} \; | sort
        ) > "$OUTFILE"

        echo "source_manifest_status{name=\"dev\"} 1" >> "$TMP"
        echo "source_manifest_timestamp{name=\"dev\"} $(date +%s)" >> "$TMP"
    else
        echo "source_manifest_status{name=\"dev\"} 0" >> "$TMP"
    fi
}
gen_md5 design  /data/design
gen_md5 finance /data/finance
gen_md5_dev

mv -f "$TMP" "$OUT"
