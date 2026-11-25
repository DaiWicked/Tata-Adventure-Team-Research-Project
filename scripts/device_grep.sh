#!/system/bin/sh
# device_grep.sh —— root 从进程外扫 /proc/<pid>/mem 里的明文特征串（纯 ASCII，避免二进制转义问题）
#
# 用法：su -c 'sh /data/local/tmp/device_grep.sh <pid> [关键词...]'
#
# 为什么用 ASCII 而不是魔数：
#   device_scan.sh 已经把整个 rw 空间扫完（2m16s，300MB+），`af 1b b1 fa`（IL2CPP 元数据头）
#   和 `1b 4c 75 61`（Lua 块头）都是 0 命中 —— 说明这两个头在内存里都不以原样存在：
#   易盾 HTPX 容器很可能把元数据头也换掉了，Lua 也可能被再包一层。
#   所以改扫"内容级"特征：元数据字符串表里必然有 mscorlib / Assembly-CSharp，
#   Lua 侧用我们已知的测试文件名 PinballTrick 之类做探针。
#
# 每个 4MB 块只读一次，一次 grep 多个模式；跳过系统 framework 的 .art/.oat 段。

P=$1
shift
[ -z "$P" ] && { echo "usage: sh device_grep.sh <pid> [kw...]"; exit 1; }
if [ $# -eq 0 ]; then
  set -- mscorlib Assembly-CSharp PinballTrick MonoBehaviour
fi

ARGS=""
for kw in "$@"; do ARGS="$ARGS -e $kw"; done

echo "pid=$P patterns=$*"
grep ' rw' /proc/$P/maps | grep -v -E '\.(art|oat|odex|vdex) |/system/|/apex/' | while read -r line; do
  range=$(echo "$line" | cut -d' ' -f1)
  s=${range%-*}; e=${range#*-}
  s=$((0x$s)); e=$((0x$e))
  len=$((e - s))
  [ "$len" -lt 1048576 ] && continue
  path=$(echo "$line" | cut -d' ' -f6)
  off=0
  while [ "$off" -lt "$len" ]; do
    blocks=$(( (len - off) / 4096 ))
    [ "$blocks" -gt 1024 ] && blocks=1024
    [ "$blocks" -le 0 ] && break
    base=$((s + off))
    # shellcheck disable=SC2086
    out=$(dd if=/proc/$P/mem bs=4096 skip=$((base/4096)) count=$blocks 2>/dev/null | grep -aob -m3 $ARGS)
    if [ -n "$out" ]; then
      echo "$out" | while IFS=: read -r rel what; do
        echo "[HIT] $(printf '0x%x' $((base + rel))) len=${#range} kw=$what path=$path range=$range"
      done
    fi
    off=$((off + blocks * 4096))
  done
done
echo "--- done ---"
