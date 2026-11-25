#!/system/bin/sh
# device_scan.sh —— 在设备上以 root 直接扫 /proc/<pid>/mem，不注入任何东西
#
# 用法（设备侧）：su -c 'sh /data/local/tmp/device_scan.sh <pid>'
#
# 为什么这样做：
#   gadget 用 wrap.<pkg> + LD_PRELOAD 注入后，易盾会看到 /data/local/tmp 下的外来 .so，
#   在 Unity 起来之前就把进程杀掉（实测每 2.5s 一对进程起来又死，libil2cpp 段数恒为 0）。
#   所以改成完全不注入：App 正常跑（实测 libil2cpp 有 8 个段），我们从进程外按 mapped range
#   逐块 dd 读 /proc/pid/mem 再 grep 魔数。toybox dd 不支持 skip_bytes，因此按 4KB 页对齐
#   (bs=4096) 分块读，保证偏移一定落在页边界上。
#
# 命中后落盘：/data/data/<pkg>/files/q_meta_*.bin（13MB）与 q_lua_*.bin（64KB）

PKG=com.lilithgame.pgame.android.cn
P=$1
OUT=/data/local/tmp
META_DUMP=$((13*1024*1024))
LUA_DUMP=$((64*1024))

[ -z "$P" ] && { echo "usage: sh device_scan.sh <pid>"; exit 1; }
[ -r /proc/$P/maps ] || { echo "no such pid: $P"; exit 1; }

META_PAT=$(printf '\257\033\261\372')   # af 1b b1 fa
LUA_PAT=$(printf '\033Lua')             # 1b 4c 75 61

echo "pid=$P"
echo "--- rw ranges ---"
grep ' rw' /proc/$P/maps | head -40
echo "--- scan ---"

grep ' rw' /proc/$P/maps | while read -r line; do
  range=$(echo "$line" | cut -d' ' -f1)
  s=${range%-*}; e=${range#*-}
  s=$((0x$s)); e=$((0x$e))
  len=$((e - s))
  [ "$len" -lt 65536 ] && continue
  path=$(echo "$line" | cut -d' ' -f6)
  off=0
  while [ "$off" -lt "$len" ]; do
    blocks=$(( (len - off) / 4096 ))
    [ "$blocks" -gt 1024 ] && blocks=1024
    [ "$blocks" -le 0 ] && break
    base=$((s + off))
    data_off=$(dd if=/proc/$P/mem bs=4096 skip=$((base/4096)) count=$blocks 2>/dev/null \
               | grep -aob -m1 -e "$META_PAT" | cut -d: -f1)
    if [ -n "$data_off" ]; then
      abs=$((base + data_off))
      f=$OUT/meta_${P}_${abs}.bin
      echo "[META] hit abs=0x$(printf %x $abs) range=$range path=$path"
      dd if=/proc/$P/mem bs=4096 skip=$((abs/4096)) count=$((META_DUMP/4096)) of=$f 2>/dev/null
      chmod 644 $f
    fi
    data_off=$(dd if=/proc/$P/mem bs=4096 skip=$((base/4096)) count=$blocks 2>/dev/null \
               | grep -aob -m1 -e "$LUA_PAT" | cut -d: -f1)
    if [ -n "$data_off" ]; then
      abs=$((base + data_off))
      f=$OUT/lua_${P}_${abs}.bin
      echo "[LUA] hit abs=0x$(printf %x $abs) range=$range path=$path"
      dd if=/proc/$P/mem bs=4096 skip=$((abs/4096)) count=$((LUA_DUMP/4096)) of=$f 2>/dev/null
      chmod 644 $f
    fi
    off=$((off + blocks * 4096))
  done
done
echo "--- done ---"
ls -l $OUT/meta_* $OUT/lua_* 2>/dev/null
