# 塔塔冒险队（com.lilithgame.pgame.android.cn）客户端安全研究

> 只做本地静态 / 待真机动态验证的**授权研究记录**：样本、脚本、证据链全部停留在本工作区，
> 不连接、不写入任何线上服务。所有结论都标注了「证据」与「还需验证」两类，避免把推测当结论。

## 一句话结论

`0.52.1` 这个包的反破解成本主要不在「改文件」，而在「改完之后怎么让服务端认」：

| 你想动的东西 | 本地能不能改 | 改了有没有用 | 卡点 |
| --- | --- | --- | --- |
| 通行证等级 / 奖励领取状态 | 能改（Lua 与数值表可解） | **只影响本地显示**，领取/结算由服务端判定 | 服务端权威 + 请求签名 |
| 金币 / 钻石数值 | 能改（内存或本地缓存） | **不进服务端账本**，重登即回滚 | 服务端账本 + 签名 + 校验 |
| 礼包价格 / 商品列表 | 能改本地表 | 下单金额由服务端算，改价会被拒 | 服务端下单接口 |
| 战斗数值（本地战斗） | 可改（Lua） | 单机战斗有效，结算上报后可能被校验 | 战报校验 |
| 皮肤/文本/图标资源 | 可改（ECB 块拼接） | 只影响自己看到的内容 | `InpackageFileHash` 哈希清单 |
| 客户端逻辑（跳过动画、去广告、加速） | 可改（Lua + so patch） | 有实际体验收益 | 易盾壳 + 签名校验 + 完整性清单 |

**所以：这个包支持「本地伪造数据」，但不支持「伪造出真实资产」。** 通行证、金币这类东西在本作里是服务端账本上的数字，客户端只负责渲染；本地改出来的数值不会被打包进任何有效请求。

## 样本

| 项 | 值 |
| --- | --- |
| 包名 | `com.lilithgame.pgame.android.cn` |
| 版本 | `0.52.1`（versionCode 4565） |
| 体积 | 342 MB / 1521 个 zip 条目 |
| 引擎 | Unity + IL2CPP（`libil2cpp.so` 61 MB）+ tolua（逻辑在 Lua） |
| 加固 | 网易易盾壳（`com.netease.nis.wrapper.MyApplication`，shellversion 4.23.196.1） |
| 网络 | 在线服务（`park_server_region: lilith`），请求签名库 `libparkcrypto.so` |
| 完整性 | `assets/InpackageFileHash.Android.jsonbin` 包内哈希清单 + `probeSoMd5Record.txt` so 指纹 |

## 目录

```
README.md                 本文件：结论卡 + 导航
docs/01-样本画像.md        包结构、assets 清单、ABI、权限、三方 SDK
docs/02-保护栈与对抗面.md   易盾壳、字符串混淆、反模拟器、签名、完整性校验
docs/03-资源容器与块加密.md  容器格式实测 + 8 字节分组 ECB 语义的证据与攻击面
docs/04-破解面评估.md       通行证/金币/商店/战斗 逐项可行性矩阵（核心结论）
docs/05-动态验证路线.md     真机 + Frida + mitmproxy 的落地步骤与 hook 点
docs/06-离线模式与状态上报.md 离线/重连/埋点三层拆解 + 判定"离线收益谁算"的实验
docs/07-pgame包索引结构.md   pgame.pkg.bin 的 token 字节律、两条字符串形式、451 条名字表
docs/08-可变面与GM入口评估.md 能改什么/GM 命令有效性/UI 入口/战斗数值/真机还能挖什么
docs/09-真机动态验证记录.md   真机实测：反调试检测链、TracerPid 遮蔽结果、设备侧新发现
docs/10-真机内存取证-明文还原.md root 直读 /proc/pid/mem：拿到解密后的元数据(HTPX)与 Lua 明文、6282 条模块表
notes/                    脚本跑出来的原始证据（可直接引用的文本）
notes/00-证据索引.md       每条结论对应哪次脚本输出、怎么复跑
scripts/                  可复现的分析脚本（01–08、10–11 纯标准库；07 依赖可选 UnityPy）
scripts/adb.sh            真机 adb 封装（绕开 Git Bash 的路径改写）
scripts/run_frida.py      把 scripts/frida/*.js 挂到设备进程并收日志（支持 attach / spawn）
scripts/pull_ranges.py    真机内存段拉取：按 maps 逐段 dd → 本地扫魔数与明文特征
scripts/10_carve_metadata.py  从 dump 里切出 HTPX 容器内的 IL2CPP 元数据并抽符号表
scripts/11_carve_lua.py       从 dump 里抽 Lua 模块路径表 + Lua 5.4 字节码块
scripts/device_*.sh       设备侧扫描脚本（dd|grep 版，留作踩坑记录；已由 pull_ranges.py 取代）
scripts/frida/            九个真机动态脚本（反调试中和 / dump 元数据 / 扫 Lua / 看签名 / 改时钟 / 看网络 / 抢跑 dump / 早 hook / 抹 TracerPid）+ hook.js / scan_only.js
captures/device/          真机取证产物（截图、Tests 目录打包、memdump），默认不入库
```

> 真机实测结论（详见 `docs/09`、`docs/10`）：**frida attach 与 `LD_PRELOAD` gadget 都会被易盾在 Unity 起来之前杀掉**，
> 但**不注入、改用 magisk root 从进程外直读 `/proc/<pid>/mem` 可以拿到全部明文** ——
> 解密后的 IL2CPP 元数据（HTPX 容器，payload 10,033,692 B）与 Lua 5.4 字节码块都在 `libc_malloc` 段里，
> 已切出 81,266 条元数据符号与 6,282 条 Lua 模块路径。

## 快速开始

```bash
# 1) 解包（也可以直接 apktool d，脚本版不依赖工具链）
py -3 scripts/01_unpack_apk.py tata.apk unpack

# 2) 抽字符串（本机没有 strings）
py -3 scripts/02_extract_strings.py unpack/lib/arm64-v8a/libil2cpp.so _il2cpp_strings.txt 6

# 3) 资源容器取证：布局 / 跨文件相关性 / 周期性 / 已知明文推断
py -3 scripts/03_probe_asset_container.py --period \
  unpack/assets/AppInfo.jsone unpack/assets/Config.jsone unpack/assets/Game.jsone \
  unpack/assets/Localization.jsone unpack/assets/Config/LanguageDbZH.luae

# 4) 全库对称算法常量扫描（判断有没有用标准 AES/DES/XXTEA）
py -3 scripts/04_scan_crypto_consts.py unpack/lib

# 5) 解易盾字符串混淆（base64 + XOR "NetEase"）
py -3 scripts/05_decode_yidun_strings.py

# 6) 包索引里还原模块/资源名（经济系统 / GM 模块名就是这里捞出来的）
py -3 scripts/06_parse_pkg_index.py unpack/assets/pgame.pkg.bin

# 7) 判定 AssetBundle 是否被 Unity 官方加密（需要 UnityPy，装到工作区）
py -3 -m pip install --target libs UnityPy
set PYTHONPATH=libs   # bash: export PYTHONPATH=libs
py -3 scripts/07_probe_bundle_unitypy.py unpack/assets/aa/catalog.bundle \
  --brute unpack/lib/arm64-v8a/libil2cpp.so
```

真机动态部分（需要自有设备，见 `docs/05` 与 `docs/09` 的实测记录）：

```bash
# 0) 封装 adb（Git Bash 会把 /data/... 改写成 Windows 路径）
bash scripts/adb.sh push tools/frida/frida-server /data/local/tmp/lgd
bash scripts/adb.sh shell su -c "'chmod 755 /data/local/tmp/lgd; nohup /data/local/tmp/lgd -D >/dev/null 2>&1 &'"
bash scripts/adb.sh forward tcp:27042 tcp:27042     # adb server 重启后要重建

# 1) attach（会被反调试杀，仅作对照）
py -3 scripts/run_frida.py scripts/frida/03_scan_lua.js --pid <PID>

# 2) spawn 模式早 hook（同样会被杀，但能观察到壳读了哪些文件）
py -3 scripts/run_frida.py scripts/frida/09_hide_tracer.js --spawn --seconds 30

# 3) 不带插桩的取证：截图 / 拉私有目录 / 看日志
bash scripts/adb.sh shell "screencap -p /data/local/tmp/s.png"
bash scripts/adb.sh pull /data/local/tmp/s.png captures/device/screen.png
```

## 仓库约定

- `tata.apk`、`unpack/`、`apktool_out/`、`jadx_out/`、`tools/`、`*.log` 全部在 `.gitignore` 里：
  体积大且可由脚本再生，不占仓库体积。
- 只提交 `docs/`、`scripts/`、`notes/`（纯文本证据）。
- 首次整理时已 `git init`；首次提交请自行执行：
  `git add -A && git commit -m "塔塔冒险队 0.52.1 客户端静态研究报告"`

## 边界

本研究只覆盖包内静态内容（反编译、资源格式、完整性机制）与**自有设备上的只读取证**（截图、日志、私有目录清单、加密格式复验）；真机插桩实测见 `docs/09`，全程未修改游戏数据、未伪造请求、未改动包体。
