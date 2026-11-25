#!/usr/bin/env python3
"""06_parse_pkg_index.py — 从 pgame.pkg.bin（半明文索引）还原包内条目名

背景: `assets/pgame.pkg` 是加密载荷，但 `assets/pgame.pkg.bin` 是**未加密的索引**：
每条记录 = 变长整型字段 + 可读路径 + 变长整型字段。因此不必解密 payload 就能知道
包内有哪些模块（Lua 脚本 / 动画 / 特效 / 英雄定义）。

本脚本不做完整 varint 反序列化（格式未公开），而是用「可打印串 + 后缀/标识符」两个
启发式把名字捞出来，够用来做模块盘点，不保证 100% 完整。

用法:
    py -3 scripts/06_parse_pkg_index.py unpack/assets/pgame.pkg.bin [out.txt]
"""
import os
import re
import sys
import collections

EXTS = (".luae", ".lbe", ".lua", ".json", ".txt", ".bytes", ".pbe", ".lpak",
        ".png", ".prefab", ".asset", ".mat", ".shader", ".anim", ".fbx",
        ".controller", ".atlas", ".fnt", ".csv", ".ab", ".dat")
PATH_CHARS = re.compile(rb"[A-Za-z0-9_\-/\.]{3,}")
IDENT = re.compile(rb"[A-Za-z][A-Za-z0-9_]{2,40}")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    src = sys.argv[1]
    dst = sys.argv[2] if len(sys.argv) > 2 else "_pkg_filelist.txt"
    data = open(src, "rb").read()
    print(f"[+] {src}: {len(data)} bytes")

    # 1) 带扩展名的路径（不需要 '/', 例如 Pb/pgame.pbe、BattleFx.luae）
    paths = set()
    for m in re.finditer(rb"[A-Za-z0-9_\-/\.]{" + str(min(3, len(data))).encode() + rb",}", data):
        s = m.group()
        low = s.lower()
        for ext in EXTS:
            i = low.find(ext.encode())
            if i > 0:
                cand = s[: i + len(ext)].decode("latin-1")
                if re.fullmatch(r"[A-Za-z0-9_\-/\.]+", cand):
                    paths.add(cand)
                break

    # 2) 无后缀的模块名：前后都被不可打印字节夹住的标识符
    idents = set()
    for m in IDENT.finditer(data):
        a, b = m.start(), m.end()
        left_ok = a == 0 or not (32 <= data[a - 1] < 127)
        right_ok = b >= len(data) or not (32 <= data[b] < 127)
        if left_ok and right_ok and len(m.group()) >= 3:
            idents.add(m.group().decode("latin-1"))

    out = sorted(paths) + [i for i in sorted(idents) if i not in paths]
    with open(dst, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out))

    print(f"[+] 带扩展名路径: {len(paths)}   裸标识符: {len(idents)}   合计写出: {len(out)} -> {dst}")

    top = collections.Counter(p.split("/")[0] for p in sorted(paths) if "/" in p)
    if top:
        print("[+] 顶层目录分布:")
        for k, v in top.most_common(20):
            print(f"    {k:16s} {v}")

    print("\n[+] 前 40 条:")
    for p in out[:40]:
        print("    " + p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
