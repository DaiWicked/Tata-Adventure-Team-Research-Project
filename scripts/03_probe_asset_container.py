#!/usr/bin/env python3
"""03_probe_asset_container.py — PGame 资源容器取证

目标: 在不暴力破解的前提下，用统计学证明 `.jsone/.luae/.pkg` 的加密性质：
  1) 容器布局    FF FF FF FF | u32 声明长度 | payload
  2) 跨文件相关性 多个文件的密文在同一偏移上是否逐字节相同
  3) 周期检测    Hamming 距离归一化，判断是否为短周期重复密钥 XOR
  4) 已知明文推断 若假定明文以某个 ASCII 前缀开头，反推 keystream 前缀

用法:
    py -3 scripts/03_probe_asset_container.py unpack/assets/AppInfo.jsone unpack/assets/Config.jsone ...
    py -3 scripts/03_probe_asset_container.py --period unpack/assets/Config/LanguageDbZH.luae
"""
import os
import struct
import sys
import statistics

MAGIC = b"\xff\xff\xff\xff"


def load(path):
    raw = open(path, "rb").read()
    if raw[:4] != MAGIC:
        return None, raw
    declared = struct.unpack("<I", raw[4:8])[0]
    return declared, raw[8:]


def popcount(x):
    return bin(x).count("1")


def hamming(a, b):
    return sum(popcount(x ^ y) for x, y in zip(a, b))


def period_test(payload, kmax=128, blocks=8):
    """重复密钥 XOR 会使某个 k 的块间汉明距离显著低于随机值 (4.0 bit/byte)。"""
    res = []
    for k in range(4, kmax + 1):
        if len(payload) < k * (blocks + 1):
            break
        chunks = [payload[i * k:(i + 1) * k] for i in range(blocks + 1)]
        ds = [hamming(chunks[i], chunks[i + 1]) / k for i in range(blocks)]
        res.append((statistics.mean(ds), k))
    res.sort()
    return res


def main():
    args = sys.argv[1:]
    mode_period = "--period" in args
    args = [a for a in args if a != "--period"]

    if not args:
        print(__doc__)
        return 1

    payloads = {}
    print("=== 1) 容器布局 ===")
    for p in args:
        declared, payload = load(p)
        size = os.path.getsize(p)
        tag = "容器" if declared is not None else "非容器(整体加密)"
        extra = f"declared=0x{declared:X}({declared})" if declared is not None else ""
        print(f"  {os.path.basename(p):28s} size={size:>9} payload={len(payload):>9} {tag} {extra}")
        payloads[p] = payload

    paths = [p for p in args if payloads[p][:4] == payloads[args[0]][:4] or True]
    if len(args) > 1:
        print("\n=== 2) 跨文件密文相关性 (XOR, 前 48 字节) ===")
        base = payloads[args[0]]
        for p in args[1:]:
            other = payloads[p]
            n = min(48, len(base), len(other))
            diff = bytes(base[i] ^ other[i] for i in range(n))
            zeros = []
            i = 0
            while i < n:
                if diff[i] == 0:
                    j = i
                    while j < n and diff[j] == 0:
                        j += 1
                    zeros.append((i, j))
                    i = j
                else:
                    i += 1
            print(f"  {os.path.basename(args[0])} ^ {os.path.basename(p)}: {diff.hex()}")
            if zeros:
                print(f"      完全相同的区间: {', '.join(f'[{a},{b})' for a, b in zeros)}")

    # 4) 已知明文推断（假定 JSON 明文以 '{"' 开头）
    print("\n=== 3) 已知明文推断 keystream 前缀 (假设明文以 '{\"' 开始) ===")
    for p in args:
        pl = payloads[p]
        if len(pl) < 2:
            continue
        ks = bytes([pl[0] ^ ord("{"), pl[1] ^ ord('"')])
        print(f"  {os.path.basename(p):28s} ks[0:2]={ks.hex()}")

    # 3) 周期检测，挑最长的一个
    target = max(args, key=lambda p: len(payloads[p]))
    print(f"\n=== 4) 周期检测 (对最长样本 {os.path.basename(target)}, payload={len(payloads[target])}) ===")
    res = period_test(payloads[target])
    print("  Hamming(bit/byte) 最小的候选密钥长度:")
    for h, k in res[:8]:
        print(f"    k={k:3d}  {h:.3f} bit/byte")
    best = res[0][0] if res else 0
    verdict = "接近随机(4.0) -> 无短周期，属带密钥流密码" if best > 3.4 else "存在短周期 -> 疑似重复密钥 XOR"
    print(f"  结论: 最优 {best:.3f} bit/byte, {verdict}")

    if mode_period:
        import collections
        pl = payloads[target]
        c = collections.Counter(pl[i:i + 16] for i in range(0, min(len(pl), 262144) - 16, 16))
        dup = [k for k, v in c.items() if v > 1]
        print(f"\n=== 5) 16 字节块重复统计 (前 256KB): 重复块数量 = {len(dup)} ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
