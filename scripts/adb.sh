#!/usr/bin/env bash
# scripts/adb.sh —— 包一层 adb，避免 Git Bash 把 /data/local/tmp/... 转成 Windows 路径
#
# 用法：
#   bash scripts/adb.sh devices
#   bash scripts/adb.sh shell "getprop ro.product.model"
#   bash scripts/adb.sh shell su -c "'id'"
#   bash scripts/adb.sh push <本地文件> /data/local/tmp/xxx
#
# 为什么要这层：MSYS/Git Bash 默认会把形如 /data/local/tmp/x 的参数按 POSIX 路径
# 转成 C:/..../data/local/tmp/x，adb 于是往 Windows 目录里推文件、报
# "remote secure_mkdirs failed"。MSYS_NO_PATHCONV=1 关掉这套转换。
set -u

ADB_DEFAULT="/c/Users/Administrator/AppData/Local/Android/Sdk/platform-tools/adb.exe"
ADB="${ADB:-$ADB_DEFAULT}"

if [ ! -x "$ADB" ]; then
  echo "[x] 找不到 adb: $ADB" >&2
  echo "    用 ADB=/path/to/adb bash scripts/adb.sh ... 覆盖" >&2
  exit 127
fi

export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

exec "$ADB" "$@"
