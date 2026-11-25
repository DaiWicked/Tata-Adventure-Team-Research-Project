#!/usr/bin/env python3
"""05_decode_yidun_strings.py — 还原网易易盾壳的 Java 层字符串混淆

算法（来自 jadx 反编译的 `a/auu/a.java`，方法 `public static String c(String str)`）:

    byte[] b = Base64.decode(str);
    for (int i = 0; i < b.length; i++) b[i] = (byte)(b[i] ^ KEY[i % KEY.length]);
    return new String(b);
    KEY = {78, 101, 116, 101, 97, 115, 101}  // ASCII "NetEase"

用途: 壳层的 assets 文件名、System.load 路径、Settings.Secure 键名全部是密文，
还原后才能确认「壳从哪加载了什么」。下面这张表就是本项目里实际解出来的关键项。

用法:
    py -3 scripts/05_decode_yidun_strings.py            # 打印内置样本表
    py -3 scripts/05_decode_yidun_strings.py IgwWCwQAAC0= Nl1C
"""
import base64
import sys

KEY = bytes([78, 101, 116, 101, 97, 115, 101])  # "NetEase"

SAMPLES = [
    "IgwWCwQAAC0=",
    "IgwWCwQAAC1TQA==",
    "IgwWCwQAAC1LBwo=",
    "YQkdBw8WFisGWhYO",
    "YRERCBEfDCw=",
    "Nl1C",
    "Nl1COldH",
    "LwEWOgQdBCwJEQE=",
    "DDAzNzEnOh0yPTEiOw==",
    "IQs=",
]


def decode(s):
    raw = base64.b64decode(s + "=" * (-len(s) % 4))
    return bytes(raw[i] ^ KEY[i % len(KEY)] for i in range(len(raw))).decode("latin-1")


def main():
    targets = sys.argv[1:] or SAMPLES
    width = max(len(t) for t in targets)
    for t in targets:
        try:
            print(f"{t:<{width}}  ->  {decode(t)}")
        except Exception as exc:  # 非法 base64 直接跳过
            print(f"{t:<{width}}  ->  <decode error: {exc}>")
    return 0


if __name__ == "__main__":
    sys.exit(main())
