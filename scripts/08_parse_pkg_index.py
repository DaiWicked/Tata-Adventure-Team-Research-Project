#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""08_parse_pkg_index.py —— 还原 assets/pgame.pkg.bin 的字符串表结构

结论摘要（完整推导见 docs/07-pgame包索引结构.md）

    pgame.pkg.bin 106,343 B、未加密，是 pgame.pkg(19MB) 的目录/符号表。
    它不是"定长记录数组"，也不是"纯路径列表"，而是
        14 字节文件头 + 「1 字节 tag 的变长 token 流」

    文件头（0x00..0x0D，14 字节）
        5d 76 05 00   f9 36 28 1f   29 01 75 19   00 00
        三段 4 字节疑似 hash/版本，末 2 字节对齐；0x0E 起是第一条记录。

    字符串编码 —— 两条已验证的形式

    形式 A：长度外置的长串（u32 LE）
        [u32 L][L 字节 ASCII]
        0x0E: 0c 00 00 00  "Pb/pgame.pbe"                  (L=12)
        0x26: 18 00 00 00  "Src/Actor/Animation.luae"      (L=24, 超过 15 只能用 A)
        全文件仅命中 3 条（第三条第 3 条是噪声 "Sz:"），说明 A 只服务少数长名。

    形式 B：紧凑 token —— 主体（约占全部名字的 99%）
        1 字节 tag，其中
            L    = tag >> 4      (高 4 位 = 字符串字节数)
            kind = tag & 0x0F    (低 4 位 = 种类)
        随后紧跟 L 字节 ASCII。
        实测（tag / L / kind / 内容）：
            0x91  9  1  "ArrowNode"
            0x84  8  4  "CthulhuF"
            0xB1 11  1  "DogElectric"
            0xC3 12  3  "ECF/Behavior"     ← 路径也走这条形式
            0x87  8  7  "Leonardo"
            0x74  7  4  "Quatern"          ← L<8 时 tag<0x80，同一公式仍成立
        校验方式：把全文件切成"可打印 ASCII 连续段"，凡段的**前一字节**满足
        tag>>4 == 段长 的，即为边界对齐的真实名字 —— 实测 273 条精确对齐，
        且所有不对齐的样本都是 tag>>4 < 段长（名字后紧贴一个可打印字节，
        如 "BattleFx" + 下一字段的 '#'），没有任何一条是 tag>>4 > 段长。
        这条「只可能少、不可能多」的方向性，是 tag=(L<<4)|kind 成立的强证据。

    因此 L 的硬上限是 15：这也是表里出现 "NormalZombi"(11)、"BigHornShee"(11)、
    "CthulhuF"(8) 这类"看起来被截断"的名字的原因 —— 12~15 字符以外的名字必须回到
    形式 A，其余按 15 字节上限切分存储。

    仍未解开（按"事不过三"约定停止深挖）
        名字之间夹着的二进制字段（`23 00` / `99 c8 18 00 00` / `70 d9 02 00` /
        `17 24 00` 等）的确切语义。它们显然是 L=0 或 L=1 的 token（kind 承载
        "int8/int32/offset" 之类），但非字符串 token 的 kind 语义表还没有证据
        来源可以证伪，静态推不出来。
        影响评估：这些字段最可能是 pgame.pkg 内的偏移/长度；对"破解面"判断
        没有增量价值（真正的资源仍在 8 字节分组加密的 pgame.pkg 里，拿到偏移
        也读不出明文），所以不继续钻。

用法
    py -3 scripts/08_parse_pkg_index.py                 # 默认 unpack/assets/pgame.pkg.bin
    py -3 scripts/08_parse_pkg_index.py <bin> -o out.txt

输出
    统计（对齐命中、kind/长度直方图、被截断名清单）+ 干净名字表（偏移 + kind + 名字）。
"""

import os
import sys
from collections import Counter

DEFAULT = os.path.join("unpack", "assets", "pgame.pkg.bin")

MIN_NAME = 6          # 名字最短长度；低于此值多为二进制区里的偶然可打印字节
MAX_RUN = 4096        # 单个 ASCII 段的上限保护


def ascii_runs(d):
    """收集所有可打印 ASCII 连续段（长度 >= MIN_NAME）。"""
    n = len(d)
    out = []
    i = 0
    while i < n:
        if 32 <= d[i] < 127:
            j = i
            while j < n and 32 <= d[j] < 127 and j - i < MAX_RUN:
                j += 1
            if j - i >= MIN_NAME:
                out.append((i, j - i))
            i = j
        else:
            i += 1
    return out


def scan_form_a(d):
    """形式 A：[u32 LE 长度][L 字节 ASCII]"""
    n = len(d)
    out = []
    for off in range(max(0, n - 4)):
        L = int.from_bytes(d[off:off + 4], "little")
        if not (3 <= L <= 400) or off + 4 + L > n:
            continue
        seg = d[off + 4:off + 4 + L]
        if all(32 <= b < 127 for b in seg) and (seg[:1].isalpha() or seg[:1] in b"_./"):
            out.append((off, L, seg.decode("ascii")))
    return out


def scan_form_b(d, runs):
    """形式 B：tag=(L<<4)|kind，取紧邻 tag 之后的 L 字节（锚定在 tag 上，不靠段长）"""
    out = []
    truncated = []
    for off, runlen in runs:
        if off < 1:
            continue
        tag = d[off - 1]
        L = tag >> 4
        kind = tag & 0x0F
        if not (MIN_NAME <= L <= 15):
            continue
        if L > runlen:
            continue                      # tag 声称的长度超过可打印段，丢弃
        seg = d[off:off + L]
        if not (seg[:1].isalpha() or seg[:1] in b"_."):
            continue
        name = seg.decode("ascii")
        out.append((off, L, kind, name, L < runlen))
        if L < runlen:
            truncated.append((off, L, runlen))
    return out, truncated


def main():
    argv = sys.argv[1:]
    src = next((a for a in argv if not a.startswith("-")), DEFAULT)
    out_path = argv[argv.index("-o") + 1] if "-o" in argv else None

    with open(src, "rb") as f:
        d = f.read()
    print("[i] %s  %d 字节" % (src, len(d)))
    print("[i] 文件头 0x00..0x0D: %s" % " ".join("%02x" % b for b in d[:14]))

    runs = ascii_runs(d)
    fa = scan_form_a(d)
    fb, truncated = scan_form_b(d, runs)

    print("\n=== 形式 A：长度外置的长串 ===")
    print("    命中 %d 条:" % len(fa))
    for off, L, s in fa:
        print("    0x%06X L=%-3d %r" % (off, L, s))

    print("\n=== 形式 B：tag=(L<<4)|kind，紧随 L 字节名字 ===")
    print("    命中 %d 条" % len(fb))
    print("    长度直方图: %s" % sorted(Counter(x[1] for x in fb).items()))
    print("    kind 直方图: %s" % sorted(Counter(x[2] for x in fb).items()))
    print("    其中 %d 条名字后面紧贴可打印字节（下一个字段恰好是 ASCII）" % len(truncated))
    print("    抽样:")
    for off, L, k, name, glue in fb[:15]:
        print("    0x%06X tag=0x%02X L=%-2d kind=%-2d %-24r%s"
              % (off, (L << 4) | k, L, k, name, "  [glue]" if glue else ""))
    if len(fb) > 15:
        print("    ...")

    names = {}
    for off, L, k, name, _ in fb:
        names.setdefault(name, (off, k))
    for off, L, s in fa:
        names.setdefault(s, (off, 0))

    ordered = sorted(names.items(), key=lambda kv: kv[1][0])
    print("\n=== 干净名字表：%d 条（去重） ===" % len(ordered))
    print("    长度范围 %d..%d" % (min(len(s) for s in names), max(len(s) for s in names)))
    print("    前 16 条: %s" % [s for s, _ in ordered[:16]])

    if out_path:
        with open(out_path, "w", encoding="utf-8", newline="\n") as f:
            f.write("# pgame.pkg.bin 字符串表  (共 %d 条)\n" % len(ordered))
            f.write("# 偏移\tkind\t名字\n")
            for s, (off, k) in ordered:
                f.write("0x%06X\t%d\t%s\n" % (off, k, s))
        print("\n[+] 已写出 %s" % out_path)


if __name__ == "__main__":
    main()
