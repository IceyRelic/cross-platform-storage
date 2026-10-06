#!/bin/bash
# 【中文注释】用途：备份端校验入口；历史版本可能有不同同代/历史调用，阅读实际命令顺序。
# 【中文注释】原版/许可证/脚本体保留；本文件为阅读副本，不替换已验证运行文件。
# 【中文注释】逐段流程、调用及原行号见旁边的“逐段解读”；续行/引号/HereDoc内部保持原样。
set -euo pipefail
python /usr/local/bin/backup-generation.py verify /backup/checksums /var/lib/node_exporter/textfile_collector
python /usr/local/bin/backup-history.py
