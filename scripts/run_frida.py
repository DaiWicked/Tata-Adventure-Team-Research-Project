#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""run_frida.py —— 把 scripts/frida/*.js 挂到设备上的目标进程并收日志

前提
    bash scripts/adb.sh forward tcp:27042 tcp:27042
    bash scripts/adb.sh shell su -c "'nohup /data/local/tmp/lgd -D >/dev/null 2>&1 &'"

用法
    py -3 scripts/run_frida.py scripts/frida/03_scan_lua.js
    py -3 scripts/run_frida.py scripts/frida/03_scan_lua.js --pid 14661 --seconds 90
    py -3 scripts/run_frida.py scripts/frida/01_neutralize_check.js --name com.lilithgame.pgame.android.cn

参数
    --pid N        指定进程号（优先）
    --name STR     按进程名找（默认 com.lilithgame.pgame.android.cn）
    --seconds N    运行多少秒后自动卸载（默认 60）
    --host H:P     远端 frida-server 地址（默认 127.0.0.1:27042）

说明
    frida 客户端装在 libs/（pip --target，全部落在工作区），所以这里把 libs/ 加到 sys.path。
"""

import argparse
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "libs"))

import frida  # noqa: E402

DEFAULT_NAME = "com.lilithgame.pgame.android.cn"


def on_message(message, data):
    if message.get("type") == "send":
        print("[js] %s" % message.get("payload"))
    elif message.get("type") == "error":
        print("[js-err] %s" % message.get("stack") or message)
    else:
        print("[msg] %s" % message)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("script")
    ap.add_argument("--pid", type=int)
    ap.add_argument("--name", default=DEFAULT_NAME)
    ap.add_argument("--seconds", type=float, default=60.0)
    ap.add_argument("--host", default="127.0.0.1:27042")
    ap.add_argument("--spawn", action="store_true",
                    help="用 spawn 模式启动并挂起在入口，加载脚本后再 resume（早 hook）")
    args = ap.parse_args()

    with open(args.script, "r", encoding="utf-8") as f:
        source = f.read()

    mgr = frida.get_device_manager()
    dev = mgr.add_remote_device(args.host)
    print("[i] device=%s" % dev)

    spawned = False
    if args.spawn:
        target = dev.spawn([args.name])
        spawned = True
        print("[i] spawn %s pid=%d（已挂起）" % (args.name, target))
    elif args.pid:
        target = args.pid
        print("[i] attach pid=%d" % target)
    else:
        target = None
        for p in dev.enumerate_processes():
            if p.name == args.name:
                target = p.pid
                break
        if target is None:
            print("[x] 没找到进程 %s（先确认 App 在前台/进程活着）" % args.name)
            return 2
        print("[i] attach %s pid=%d" % (args.name, target))

    session = dev.attach(target)
    script = session.create_script(source)
    script.on("message", on_message)
    script.load()
    print("[i] script loaded: %s" % os.path.basename(args.script))

    if spawned:
        dev.resume(target)
        print("[i] resumed pid=%d" % target)

    deadline = time.time() + args.seconds
    try:
        while time.time() < deadline:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[i] interrupted")
    finally:
        try:
            session.detach()
            print("[i] detached")
        except Exception as exc:  # noqa: BLE001
            print("[!] detach 失败: %s" % exc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
