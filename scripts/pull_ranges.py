"""pull_ranges.py —— 从设备进程直接把内存段拉回本地，用 Python 扫魔数与明文特征

为什么走这条路：
  - frida/gadget 注入会被易盾在 Unity 起来之前杀掉（实测进程对起对死，libil2cpp 段数恒 0）；
  - 设备侧 `dd | grep -aob` 的偏移不可信；mksh 对 >4GB 的 16 进制地址做算术会溢出，
    所以偏移一律在 Python 里算成十进制，再交给 dd。
  - `adb exec-out` 是二进制安全的（`adb shell` 会做 CRLF 处理），dd 输出直接落到本地文件。

用法：
  py -3 scripts/pull_ranges.py 23728 --list                 # 只列候选段
  py -3 scripts/pull_ranges.py 23728 --range 0x18e00000:10485760
  py -3 scripts/pull_ranges.py 23728 --auto --min 8 --max 200   # 自动拉 8~200MB 的非系统段
"""
import argparse
import os
import subprocess
import sys

ADB = os.environ.get("ADB") or r"C:\Users\Administrator\AppData\Local\Android\Sdk\platform-tools\adb.exe"
OUT_DIR = os.path.join("captures", "device", "memdump")
SKIP_PATH_RE = ("/system/", "/apex/", "dalvik", "mali", "jit-cache", "free list", ".art", ".oat", "/dev/")


def adb(args, binary=False):
    cmd = [ADB] + args
    if binary:
        return subprocess.run(cmd, stdout=subprocess.PIPE, check=True).stdout
    return subprocess.run(cmd, stdout=subprocess.PIPE, check=True).stdout.decode("utf-8", "replace")


def read_maps(pid):
    raw = adb(["shell", "su", "-c", "cat /proc/%s/maps" % pid])
    rows = []
    for ln in raw.splitlines():
        parts = ln.split(None, 5)
        if len(parts) < 5 or "rw" not in parts[1]:
            continue
        a, b = parts[0].split("-")
        start, end = int(a, 16), int(b, 16)
        path = parts[5].strip() if len(parts) > 5 else ""
        if any(t in path for t in SKIP_PATH_RE):
            continue
        rows.append((end - start, start, path))
    rows.sort(reverse=True)
    return rows


def pull(pid, start, size, name):
    os.makedirs(OUT_DIR, exist_ok=True)
    dst = os.path.join(OUT_DIR, name)
    blocks = size // 4096
    data = adb(["exec-out", "su", "-c",
                "dd if=/proc/%s/mem bs=4096 skip=%d count=%d 2>/dev/null" % (pid, start // 4096, blocks)],
               binary=True)
    with open(dst, "wb") as f:
        f.write(data)
    print("  pulled %-28s %8.1f MB -> %s" % (name, len(data) / 1048576.0, dst))
    return dst


def scan(path):
    data = open(path, "rb").read()
    report = []
    for label, magic in (("meta-magic", b"\xaf\x1b\xb1\xfa"), ("lua-magic", b"\x1bLua")):
        idx = data.find(magic)
        report.append("%s=%s" % (label, ("0x%x" % idx) if idx >= 0 else "-"))
    for label, pat in (("mscorlib", b"mscorlib"), ("Assembly-CSharp", b"Assembly-CSharp"),
                       ("PinballTrick", b"PinballTrick"), ("MonoBehaviour", b"MonoBehaviour")):
        idx = data.find(pat)
        report.append("%s=%s" % (label, ("0x%x" % idx) if idx >= 0 else "-"))
    print("  scan %-28s %s" % (os.path.basename(path), " ".join(report)))
    return " ".join(report)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pid")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--range", action="append", default=[])
    ap.add_argument("--auto", action="store_true")
    ap.add_argument("--min", type=float, default=8.0)
    ap.add_argument("--max", type=float, default=200.0)
    args = ap.parse_args()

    if args.list or not (args.range or args.auto):
        rows = read_maps(args.pid)
        print("rw ranges (excl system/dalvik/mali): %d, total %.0f MB" % (len(rows), sum(r[0] for r in rows) / 1048576))
        for size, start, path in rows:
            if size / 1048576.0 < 4:
                continue
            print("  %8.1f MB  0x%010x  %s" % (size / 1048576.0, start, path[:60]))
        return

    targets = []
    for spec in args.range:
        a, b = spec.split(":")
        targets.append((int(a, 16), int(b, 16) if b.startswith("0x") else int(b), ""))
    if args.auto:
        for size, start, path in read_maps(args.pid):
            if args.min <= size / 1048576.0 <= args.max:
                targets.append((start, size, path))

    for start, size, path in targets:
        name = "pid%s_0x%010x_%dMB.bin" % (args.pid, start, max(1, size // 1048576))
        pull(args.pid, start, size, name)
        scan(os.path.join(OUT_DIR, name))


if __name__ == "__main__":
    sys.exit(main())
