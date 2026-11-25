#!/usr/bin/env python3
"""01_unpack_apk.py — 纯标准库 APK 解包与结构统计

用法:
    py -3 scripts/01_unpack_apk.py tata.apk unpack

设计原则: 只做可复现的机械动作（zip 解压 + 统计），不依赖 apktool/jadx，
便于在任何机器上重建 `unpack/` 证据目录。
"""
import os
import sys
import zipfile
import collections

MAGIC = b"\xff\xff\xff\xff"


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f}{unit}" if unit != "B" else f"{n}B"
        n /= 1024.0


def main():
    apk = sys.argv[1] if len(sys.argv) > 1 else "tata.apk"
    outdir = sys.argv[2] if len(sys.argv) > 2 else "unpack"
    if not os.path.exists(apk):
        print(f"[!] 找不到 {apk}")
        return 1

    zf = zipfile.ZipFile(apk)
    items = [(i.filename, i.file_size) for i in zf.infolist()]
    print(f"[+] APK: {apk}  size={human(os.path.getsize(apk))}  entries={len(items)}")

    top = collections.Counter()
    top_size = collections.Counter()
    for name, size in items:
        head = name.split("/")[0] + "/" if "/" in name else "<root>"
        top[head] += 1
        top_size[head] += size
    print("\n[+] 顶层目录分布 (条目数 / 解压后体积)")
    for head, cnt in top.most_common():
        print(f"    {head:16s} {cnt:5d}  {human(top_size[head])}")

    print("\n[+] 体积 Top 20 条目")
    for name, size in sorted(items, key=lambda x: -x[1])[:20]:
        print(f"    {human(size):>9}  {name}")

    os.makedirs(outdir, exist_ok=True)
    zf.extractall(outdir)
    print(f"\n[+] 已解压到 {outdir}/")

    # 资源容器格式探测：FF FF FF FF + u32 长度
    print("\n[+] 疑似 PGame 加密容器 (前 4 字节 FF FF FF FF) 的 assets 文件")
    base = os.path.join(outdir, "assets")
    if os.path.isdir(base):
        for root, _dirs, files in os.walk(base):
            for fn in files:
                p = os.path.join(root, fn)
                if os.path.getsize(p) < 8:
                    continue
                with open(p, "rb") as f:
                    if f.read(4) == MAGIC:
                        f.seek(4)
                        declared = int.from_bytes(f.read(4), "little")
                        sz = os.path.getsize(p)
                        rel = os.path.relpath(p, outdir).replace("\\", "/")
                        print(f"    {human(sz):>9}  len=0x{declared:X}  {rel}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
