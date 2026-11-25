#!/usr/bin/env python3
"""07_probe_bundle_unitypy.py — 判断 Unity AssetBundle 是否被加密、密钥能否就地爆破

依赖: UnityPy（可选）。装到工作区:
    py -3 -m pip install --target libs UnityPy
    set PYTHONPATH=libs

背景（本项目实测）:
    `assets/aa/catalog.bundle`、`assets/aa/Android/inpackage_aa_1.lpak` 的头是 `UnityFS`，
    但版本串被改成 `5.x.x` / `0.0.0`。不设 fallback 版本时 UnityPy 会报
    "No valid Unity version found"; 设了之后会报
    "The BundleFile is encrypted, but no key was provided!"，并给出
    key_sig / data_sig —— 这就是 Unity 官方 ArchiveStorageManager（UnityCN）加密。

用法:
    py -3 scripts/07_probe_bundle_unitypy.py unpack/assets/aa/catalog.bundle
    py -3 scripts/07_probe_bundle_unitypy.py unpack/assets/aa/catalog.bundle --brute unpack/lib/arm64-v8a/libil2cpp.so
"""
import sys


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    bundle = sys.argv[1]
    brute_targets = []
    if "--brute" in sys.argv:
        brute_targets = sys.argv[sys.argv.index("--brute") + 1:]

    try:
        import UnityPy
        from UnityPy.helpers import ArchiveStorageManager
    except ImportError:
        print("[!] 需要 UnityPy: py -3 -m pip install --target libs UnityPy && set PYTHONPATH=libs")
        return 2

    UnityPy.config.FALLBACK_UNITY_VERSION = "2021.3.0f1"
    key_sig = data_sig = None
    try:
        env = UnityPy.load(bundle)
        counts = {}
        for obj in env.objects:
            counts[obj.type.name] = counts.get(obj.type.name, 0) + 1
        print(f"[+] 未加密，可直接读: {counts}")
        return 0
    except Exception as exc:
        msg = str(exc)
        print(f"[+] 解析失败: {type(exc).__name__}: {msg.splitlines()[0]}")
        for token in ("key_sig", "data_sig"):
            if token in msg:
                seg = msg.split(token + " = ")[-1].split(",")[0].strip()
                if token == "key_sig":
                    key_sig = seg
                else:
                    data_sig = seg
    if not (key_sig and data_sig):
        print("[!] 不是 UnityCN 加密，或 UnityPy 版本不同（未拿到 key_sig/data_sig）")
        return 0

    print(f"[+] 判定: Unity ArchiveStorageManager 加密  key_sig={key_sig}  data_sig={data_sig}")
    print("    含义: 目录信息被加密，必须提供 16 字节 key 才能解析；key 通常运行时拼装。")
    for t in brute_targets:
        try:
            k = ArchiveStorageManager.brute_force_key(t, key_sig, data_sig)
            print(f"    brute {t} -> {k.hex() if k else None}")
        except Exception as exc:
            print(f"    brute {t} -> ERR {type(exc).__name__}: {exc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
