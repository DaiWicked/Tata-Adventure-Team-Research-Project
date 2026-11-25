"""12_scan_gm_surface.py —— 从内存 dump 里把 GM 相关的字符串与"前置位"候选一起挖出来

P0 的问题只有一个：**GM 面板的命令是客户端能自己打开的，还是要服务端授权？**
判据：命令表里每条命令是否带 `need_gm` / `need_server` / `minGmLevel` / `whitelist` 之类的前置位，
以及这些前置位的值是不是由服务端下发。

本脚本不做完整 Lua 字节码反编译（切出来的块是"堆碎片"，不是完整文件，硬解会中途失败），
而是先把**字符串层**的证据挖干净：Lua 字节码的常量池里所有名字都是明文，
所以"有哪些命令名、有哪些前置位名"能直接看到；名字之间的邻接关系还能给出同函数簇的线索。

用法：
  py -3 scripts/12_scan_gm_surface.py captures/device/memdump/pid23728_0x7d9091a000_144MB.bin
输出：notes/12-gm-strings.txt
"""
import argparse
import os
import re
from collections import Counter

PRINT = re.compile(rb"[ -~]{3,80}")
IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{2,60}$")

GM_WORD = re.compile(r"(?i)(^|[^a-z])(gm|gmc|debug|cheat|test|qa)([^a-z]|$)")
GATE_WORD = re.compile(r"(?i)(need|require|allow|permit|enable|check|verify|limit|white|black|level|auth)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dump")
    ap.add_argument("--out", default=os.path.join("notes", "12-gm-strings.txt"))
    args = ap.parse_args()

    data = open(args.dump, "rb").read()
    strs = Counter()
    for m in PRINT.finditer(data):
        s = m.group(0).decode("ascii", "replace")
        if IDENT.match(s) or "/" in s or "://" in s:
            strs[s] += 1
    print("dump=%s  可打印标识串 %d 种" % (args.dump, len(strs)))

    gm = sorted(s for s in strs if GM_WORD.search(s))
    gate = sorted(s for s in strs if GATE_WORD.search(s))
    # GM 名里同时带前置位词的，最可疑（同一条命令的字段名）
    both = sorted(s for s in gm if GATE_WORD.search(s))

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write("# GM 相关字符串（内存 dump，含出现次数）\n")
        f.write("## A. 含 gm/debug/cheat/test/qa 的标识（%d 条）\n" % len(gm))
        for s in gm:
            f.write("%-60s x%d\n" % (s, strs[s]))
        f.write("\n## B. 前置位/权限类词（%d 条）\n" % len(gate))
        for s in gate:
            f.write("%-60s x%d\n" % (s, strs[s]))
        f.write("\n## C. 同时含 GM 与前置位词（%d 条，最高优先级）\n" % len(both))
        for s in both:
            f.write("%-60s x%d\n" % (s, strs[s]))
    print("A=%d  B=%d  C=%d  → %s" % (len(gm), len(gate), len(both), args.out))
    print("C 组样例:", ", ".join(both[:20]))


if __name__ == "__main__":
    raise SystemExit(main())
