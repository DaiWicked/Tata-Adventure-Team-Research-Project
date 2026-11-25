"""10_carve_metadata.py —— 从设备内存 dump 里切出解密后的 IL2CPP 元数据，并抽出符号表

发现（2026-11-25，真机 pid 23728，dump `captures/device/memdump/pid23728_0x7d62924000_9MB.bin`）：
  该段开头就是 HTPX 容器：
      00-03  "HTPX"
      04-07  u32 总长 = 10,033,692（== APK 里 global-metadata.dat 的字节数）
      08-..  明文元数据（这就是易盾运行时解密出来的东西）
  验证点：
      payload+0xD24A8 起是字符串表，开头就是 'Assembly-CSharp.dll\\0<Module>\\0EmbeddedAtt…'
      payload+0x2C288 起是 stringLiteral 表（u32 长度 + u32 索引 的配对）
      payload+0xA6120 起是 stringLiteral 数据（'…attempt to index a nil value' 等 Lua 报错串）
  **注意**：payload 头部没有 `af 1b b1 fa`（sanity）也没有 version —— 易盾把这两项换掉了，
  所以现成工具（Il2CppDumper）会判定"不是 metadata"。本脚本因此自己做两件事：
      1) 切出 payload 存盘（global-metadata.htpx.bin），供后续按字段偏移直接读；
      2) 不依赖 sanity/version，靠"字符串表 + stringLiteral 表"直接把符号名抽出来。

用法：
  py -3 scripts/10_carve_metadata.py captures/device/memdump/pid23728_0x7d62924000_9MB.bin
  py -3 scripts/10_carve_metadata.py <dump> -o unpack/metadata --strings notes/10-metadata-strings.txt
"""
import argparse
import os
import re
import struct

PRINTABLE = re.compile(rb"^[\x20-\x7e]{3,}$")


def find_container(data):
    """定位 HTPX 容器：magic + 总长，且总长 < 剩余长度"""
    pos = 0
    while True:
        pos = data.find(b"HTPX", pos)
        if pos < 0:
            return None
        if pos + 8 <= len(data):
            size = struct.unpack_from("<I", data, pos + 4)[0]
            if 1024 < size <= len(data) - pos - 8:
                return pos, size
        pos += 4


def extract_strings(payload, string_off):
    """字符串表：从 string_off 到结尾，\\0 分隔"""
    blob = payload[string_off:]
    out = []
    for part in blob.split(b"\x00"):
        if PRINTABLE.match(part):
            out.append(part.decode("ascii", "replace"))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dump")
    ap.add_argument("-o", "--outdir", default=os.path.join("unpack", "metadata"))
    ap.add_argument("--strings", default=os.path.join("notes", "10-metadata-strings.txt"))
    args = ap.parse_args()

    data = open(args.dump, "rb").read()
    loc = find_container(data)
    if not loc:
        print("未找到 HTPX 容器")
        return 1
    pos, size = loc
    payload = data[pos + 8: pos + 8 + size]
    print("HTPX @0x%x  总长=%d  实际切出=%d" % (pos, size, len(payload)))

    head = struct.unpack_from("<16I", payload, 0)
    print("header u32[0..15] = " + " ".join("0x%x" % v for v in head))
    string_off = head[4]
    print("字符串表偏移 = 0x%x（header[4]）" % string_off)

    os.makedirs(args.outdir, exist_ok=True)
    dst = os.path.join(args.outdir, "global-metadata.htpx.bin")
    with open(dst, "wb") as f:
        f.write(payload)
    print("已写 %s (%d B)" % (dst, len(payload)))

    names = extract_strings(payload, string_off)
    seen, uniq = set(), []
    for n in names:
        if n not in seen:
            seen.add(n)
            uniq.append(n)
    os.makedirs(os.path.dirname(args.strings) or ".", exist_ok=True)
    with open(args.strings, "w", encoding="utf-8") as f:
        f.write("# IL2CPP 元数据字符串表（来自内存 dump，共 %d 条 / 去重 %d）\n" % (len(names), len(uniq)))
        for n in uniq:
            f.write(n + "\n")
    print("符号/字符串 %d 条（去重 %d）→ %s" % (len(names), len(uniq), args.strings))

    kw = ("Pass", "Gold", "Coin", "Cashier", "Charge", "Season", "Shop", "Gift", "GM", "Gm", "Debug", "Idle", "Report")
    for k in kw:
        hit = [n for n in uniq if k in n][:8]
        if hit:
            print("  [%s] %s" % (k, ", ".join(hit)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
