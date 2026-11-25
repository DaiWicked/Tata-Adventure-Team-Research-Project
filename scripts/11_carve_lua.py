"""11_carve_lua.py —— 从内存 dump 里抽出解密后的 Lua：模块路径表 + 字节码块

背景：静态侧 pgame.pkg / *.luae 全是 8 字节分组加密，拿不到明文。真机 dump（不注入，
root 直读 /proc/<pid>/mem）证明运行时明文在 `[anon:libc_malloc]` 144MB 段里，
`captures/device/memdump/pid23728_0x7d9091a000_144MB.bin` 命中：
  - 51 处 Lua 5.4 预编译块头 `1b 4c 75 61 54 00 19 93 0d 0a 1a 0a`（0x54='T' = 5.4）
  - 一整张模块路径表：`Src/UI/Debug/GMBaseTab.luae`、`Src/UI/Debug/Tabs/GMGVGTab.luae`、
    `GMKolTab`/`GMLogTab`/`GMMixTab`/`GMSDKTab`、`Src/Tools/ProtoTestForge.luae` …
  - 函数级 chunk 名：`Src_UI_Pinball_Scene_PinballScene`、`Src_UI_PinballBuff_PinballTrickCalc` …

本脚本：
  1) 抽所有 `...luae` 路径（去重排序）→ notes/11-lua-modules.txt
  2) 以每个 `1bLua` 头为起点切块（到下一个头或 +512KB 为界），写 unpack/lua/*.luac
  3) 打印每个块的头部 chunk 名（Lua 头后面紧跟的 source name 串）

用法：py -3 scripts/11_carve_lua.py captures/device/memdump/pid23728_0x7d9091a000_144MB.bin
"""
import argparse
import os
import re

PATH_RE = re.compile(rb"[A-Za-z0-9_/\.\-]{4,120}\.luae")
LUA_SIG = b"\x1bLua"
MAX_CHUNK = 512 * 1024


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dump")
    ap.add_argument("--modules", default=os.path.join("notes", "11-lua-modules.txt"))
    ap.add_argument("--outdir", default=os.path.join("unpack", "lua"))
    args = ap.parse_args()

    data = open(args.dump, "rb").read()
    print("dump=%s (%d B)" % (args.dump, len(data)))

    paths = sorted({m.group(0).decode("ascii") for m in PATH_RE.finditer(data)})
    os.makedirs(os.path.dirname(args.modules) or ".", exist_ok=True)
    with open(args.modules, "w", encoding="utf-8") as f:
        f.write("# Lua 模块路径（内存 dump 还原，共 %d 条）\n" % len(paths))
        for p in paths:
            f.write(p + "\n")
    print("模块路径 %d 条 → %s" % (len(paths), args.modules))

    hits = [m.start() for m in re.finditer(re.escape(LUA_SIG), data)]
    print("Lua 块头 %d 处" % len(hits))
    os.makedirs(args.outdir, exist_ok=True)
    for i, off in enumerate(hits):
        end = hits[i + 1] if i + 1 < len(hits) else min(off + MAX_CHUNK, len(data))
        chunk = data[off:min(end, off + MAX_CHUNK)]
        # 头部之后通常紧跟 source name（可打印串），取出来当文件名的一部分
        name = ""
        m = re.match(rb"[\x1bLua].{0,32}?([A-Za-z][A-Za-z0-9_/\.]{3,60})", chunk, re.S)
        if m:
            name = re.sub(r"[^A-Za-z0-9_\.]+", "_", m.group(1).decode("ascii", "replace"))[:40]
        ver = chunk[4] if len(chunk) > 4 else 0
        fn = os.path.join(args.outdir, "h%02d_0x%08x_v%02x_%s.luac" % (i, off, ver, name or "chunk"))
        with open(fn, "wb") as f:
            f.write(chunk)
        print("  %-70s %6d B  ver=0x%02x" % (os.path.basename(fn), len(chunk), ver))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
