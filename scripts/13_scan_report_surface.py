#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""13_scan_report_surface.py — 扫「战报/结算上报面」的标识符

为什么需要：P0 证明 GM 命令要过服务端权限，那客户端唯一还能"影响资产"的地方就是
结算上报（docs/12）。这个脚本不猜结构，只把内存里跟「上报入口 / 战斗字段 /
复算校验」有关的标识符分三段列出来，作为判断依据。

用法:
    py -3 scripts/13_scan_report_surface.py <dump.bin> [-o notes/13-report-strings.txt]

分段:
    A 上报入口   Req*/Pack*Field/Report*/Submit*
    B 字段名     战斗结算里会被客户端声明的数值与版本字段
    C 复算校验   Simulator/Random/BtRecord/CheckVersion/Seed/Replay
"""
import re
import sys

IDENT = re.compile(rb"[A-Za-z_][A-Za-z0-9_]{3,40}")

# A: 客户端主动发起的请求 / 打包函数
REQ_PREFIX = re.compile(r"^(Req|Pack|Report|Submit|Send)[A-Z][A-Za-z0-9_]*$")
# B: 战斗结果里"客户端说了算"的候选字段
FIELD_WORD = re.compile(
    r"(?i)(damage|rounds?|kill|left|death|combo|dps|score|star|wave|hp|"
    r"count|limit|amount|time|version|bt|seed)"
)
FIELD_ALLOW = re.compile(r"^[a-z][A-Za-z0-9_]{3,30}$")
# C: 服务端复算 / 校验相关
VERIFY_WORD = re.compile(
    r"(?i)(simulat|random|btrecord|btinput|checkversion|verify|replay|"
    r"determin|samplelog|anticheat|riskcontrol)"
)

# 噪声：纯 UI / 资源 / 引擎里的高频词，跟结算无关
NOISE = re.compile(
    r"(?i)^(SFX|txui|pbui|prefab|Assets|Sprite|Atlas|Mipmap|hlslcc|Unity|"
    r"Shader|Material|Texture|Animator|Cinemachine|TMP)"
)


def collect(path):
    data = open(path, "rb").read()
    counts = {}
    for m in IDENT.finditer(data):
        s = m.group().decode("ascii", "ignore")
        counts[s] = counts.get(s, 0) + 1
    return data, counts


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    path = sys.argv[1]
    out = "notes/13-report-strings.txt"
    if "-o" in sys.argv:
        out = sys.argv[sys.argv.index("-o") + 1]

    data, counts = collect(path)

    sec_a = sorted(k for k in counts if REQ_PREFIX.match(k) and not NOISE.match(k))
    sec_b = sorted(
        k
        for k in counts
        if FIELD_ALLOW.match(k) and FIELD_WORD.search(k) and not NOISE.match(k)
        and not k.startswith(("get", "set", "Get", "Set", "On", "is", "Is"))
    )
    sec_c = sorted(k for k in counts if VERIFY_WORD.search(k) and not NOISE.match(k))

    lines = [
        "# 战报/结算上报面扫描  源: %s" % path,
        "# 标识符总数 %d" % len(counts),
        "",
        "## A. 上报入口 (%d)" % len(sec_a),
    ]
    lines += ["%-56s x%d" % (k, counts[k]) for k in sec_a]
    lines += ["", "## B. 字段候选 (%d)" % len(sec_b)]
    lines += ["%-56s x%d" % (k, counts[k]) for k in sec_b]
    lines += ["", "## C. 复算/校验 (%d)" % len(sec_c)]
    lines += ["%-56s x%d" % (k, counts[k]) for k in sec_c]

    # 关键字段的一次性上下文（便于人工判断是不是同一个协议消息）
    keys = [b"PackBattleReqField", b"BtInputExt", b"battleCheckVersion", b"ReportBattleLog"]
    lines += ["", "## D. 关键标识符上下文"]
    for k in keys:
        for i, m in enumerate(re.finditer(re.escape(k), data)):
            if i >= 2:
                break
            s = data[max(0, m.start() - 200): m.start() + 300]
            txt = bytes(c if 32 <= c < 127 else 46 for c in s).decode("ascii")
            txt = re.sub(r"\.{4,}", " | ", txt)
            lines.append("@0x%08x %s: %s" % (m.start(), k.decode(), txt))

    text = "\n".join(lines) + "\n"
    with open(out, "w", encoding="utf-8") as f:
        f.write(text)
    print("A=%d B=%d C=%d -> %s" % (len(sec_a), len(sec_b), len(sec_c), out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
