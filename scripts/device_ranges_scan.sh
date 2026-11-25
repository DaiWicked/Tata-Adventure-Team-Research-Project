#!/system/bin/sh
# device_ranges_scan.sh —— 逐段 dump 再 grep（不靠管道，避免 dd|grep 偏移错乱）
#
# 前情：device_scan.sh 用 `dd | grep -aob` 扫完整个 rw 空间，meta/lua 魔数 0 命中；
#       device_grep.sh 的管道方式解析出来的偏移不可靠（kw/path 全空、同一偏移重复 11 次）。
#       所以改成"先落盘再 grep 文件"：dd of=FILE 一定有确定的字节数，grep 在文件上取偏移才可信。
#
# 过滤：只要 size 在 8MB..200MB、且不是 dalvik/mali/jit/free-list 的段 ——
#       10,033,692 B 的 global-metadata.dat 解密后最可能落在这种 malloc/anon 大段里。
#
# 用法：su -c 'sh /data/local/tmp/device_ranges_scan.sh <pid>'

P=$1
[ -z "$P" ] && { echo "usage: sh device_ranges_scan.sh <pid>"; exit 1; }
T=/data/local/tmp/grep_tmp.bin

echo "pid=$P"
grep ' rw' /proc/$P/maps \
  | grep -v -E '/system/|/apex/|\.art|\.oat|dalvik|mali|jit-cache|free list|/dev/' \
  | while read -r line; do
      range=$(echo "$line" | cut -d' ' -f1)
      s=${range%-*}; e=${range#*-}
      s=$((0x$s)); e=$((0x$e))
      len=$((e - s))
      { [ "$len" -lt $((8*1024*1024)) ] || [ "$len" -gt $((200*1024*1024)) ]; } && continue
      path=$(echo "$line" | cut -d' ' -f6)
      dd if=/proc/$P/mem bs=4096 skip=$((s/4096)) count=$((len/4096)) of=$T 2>/dev/null
      got=$(wc -c < $T)
      m=$(grep -aob -m1 -e mscorlib $T | cut -d: -f1)
      a=$(grep -aob -m1 -e Assembly-CSharp $T | cut -d: -f1)
      l=$(grep -aob -m1 -e PinballTrick $T | cut -d: -f1)
      printf 'range=0x%x size=%.1fMB got=%s mscorlib=%s asmcsharp=%s pinball=%s path=%s\n' \
        "$s" "$(echo "$len" | awk '{print $1/1048576}')" "$got" "${m:--}" "${a:--}" "${l:--}" "$path"
      rm -f $T
    done
echo "--- done ---"
