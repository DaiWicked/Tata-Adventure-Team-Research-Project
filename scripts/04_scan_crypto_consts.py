#!/usr/bin/env python3
"""04_scan_crypto_consts.py — 全库对称算法常量指纹扫描

思路: 若目标使用标准 AES / DES / Blowfish / ChaCha20 / XXTEA，算法特征常量会原样
出现在 .so 里（S 盒、IP 置换表、sigma 常量、delta）。扫不到，就说明是自定义或
非标准参数实现——这时候静态路子基本到此为止，必须动态 hook。

用法:
    py -3 scripts/04_scan_crypto_consts.py unpack/lib
    py -3 scripts/04_scan_crypto_consts.py unpack/lib --only arm64-v8a
"""
import glob
import os
import sys

CONSTANTS = {
    "aes_sbox": "637c777bf26b6fc5",          # AES S-box 前 8 字节
    "aes_te0": "c66363a5f87c7c84",           # AES T-table
    "des_IP": "3a26c5ff2c2efb5e",            # DES 初始置换表片段
    "blowfish_pi": "243f6a8885a308d3",       # Blowfish P 数组（π 展开）
    "chacha_sigma": "65787061",              # "expa" (expand 32-byte k)
    "xxtea_delta": "b979379e",               # 0x9E3779B9
    "tea_golden": "b979379e",
    "md5_init": "0123456789abcdeffedcba9876543210",
    "sha256_k": "428a2f98d728ae22",
    "sm4_fk": "a3b1bac656aa3350",
}


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    root = sys.argv[1]
    only = None
    if "--only" in sys.argv:
        only = sys.argv[sys.argv.index("--only") + 1]

    files = sorted(glob.glob(os.path.join(root, "**", "*.so"), recursive=True))
    if only:
        files = [f for f in files if only in f.replace("\\", "/")]
    print(f"[+] 扫描 {len(files)} 个 .so\n")
    print(f"{'library':44s} {'size':>10}  hits")
    for f in files:
        data = open(f, "rb").read()
        hits = {}
        for name, hexv in CONSTANTS.items():
            i = data.find(bytes.fromhex(hexv))
            if i >= 0:
                hits[name] = i
        rel = f.split("lib" + os.sep)[-1] if "lib" + os.sep in f else f
        print(f"{rel:44s} {len(data):>10}  {hits if hits else '-'}")
    print("\n[!] 未命中不代表没有加密：自定义参数（非标准 S 盒/非标准 delta）不会留下常量。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
