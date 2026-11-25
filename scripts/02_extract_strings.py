#!/usr/bin/env python3
"""02_extract_strings.py — 从 .so / .dex / 任意二进制提取可读字符串

用法:
    py -3 scripts/02_extract_strings.py unpack/lib/arm64-v8a/libil2cpp.so _il2cpp_strings.txt [最小长度]

为什么自备实现: 本机 Windows 环境没有 strings/objdump/readelf，
且样本体积大（libil2cpp 61MB），需要可控的最小长度与编码范围。
"""
import os
import re
import sys

# 可打印 ASCII：0x20-0x7E，外加 UTF-8 中文字节序列放行（按原始字节保留）
RUN = re.compile(rb"[\x20-\x7e]{4,}")


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    src, dst = sys.argv[1], sys.argv[2]
    minlen = int(sys.argv[3]) if len(sys.argv) > 3 else 6
    if not os.path.exists(src):
        print(f"[!] 找不到 {src}")
        return 1

    data = open(src, "rb").read()
    out = []
    for m in RUN.finditer(data):
        s = m.group()
        if len(s) >= minlen:
            out.append(s.decode("latin-1"))
    with open(dst, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out))
    print(f"[+] {src} ({len(data)} bytes) -> {dst}: {len(out)} strings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
