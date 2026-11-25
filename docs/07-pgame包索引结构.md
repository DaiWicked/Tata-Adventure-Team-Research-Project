# 07 · pgame.pkg.bin 索引结构

> 对象：`unpack/assets/pgame.pkg.bin`（106,343 B，**未加密**）
> 结论一句话：它是一份「14 字节头 + 单字节 tag 的变长 token 流」，字符串用 `tag=(长度<<4)|种类` 紧凑编码，>15 字符的名字退回 u32 长度前缀形式。**它只是目录/符号表，不含任何经济数值**，所以解到这里对"能不能伪造数据"没有增益。

---

## 1. 为什么值得先解它

`pgame.pkg`（19 MB）本体是 `FF FF FF FF + u32 长度 + 8 字节分组密文`，静态打不开；而 106 KB 的 `.bin` 是明文，且包含全部包内条目名与经济系统模块名（`xDPass`/`AGold`/`uCashierL`…）。它是**唯一能在不动态调试的前提下看到"包里有什么"的入口**。

本文件回答三件事：
1. 包里有哪些模块（→ 决定"通行证/金币"逻辑在客户端还是服务端）；
2. 条目名怎么编码（→ 以后拿到解密 key，靠它直接定位条目）；
3. 名字之间的字段是什么（→ 偏移/长度表，**未解，见 §7**）。

---

## 2. 文件头（0x00..0x0D，14 字节）

```
offset  bytes                       读数
0x00    5d 76 05 00                 u32 = 0x0005765D = 358,493   （既非条目数也非文件大小，疑为 hash/版本号）
0x04    f9 36 28 1f                 u32 = 0x1F2836F9            （hash 候选）
0x08    29 01 75 19                 u32 = 0x19750129            （hash 候选）
0x0C    00 00                       2 字节对齐填充
0x0E    --                          第一条记录起点
```

- 358,493 与任何可测量值都不对应（条目数 451、文件 106,343、pgame.pkg 19,472,168），所以头部更像**内容指纹**而不是计数。这一点无法静态证伪，按下不表。
- `0x0E` 是硬起点：从 0x0E 起第一条记录的 u32 长度恰好 = 12，且紧随的 12 字节是 `Pb/pgame.pbe`（合法条目名）。

---

## 3. 字符串形式 A：长度外置（只服务长名）

```
[u32 LE 长度 L][L 字节 ASCII]
```

实测全文件仅 **3 条**命中：

| 偏移 | L | 内容 | 说明 |
|---|---|---|---|
| 0x00000E | 12 | `Pb/pgame.pbe` | 包内主数据文件名 |
| 0x000026 | 24 | `Src/Actor/Animation.luae` | 24 字符 > 15，只能用 A |
| 0x008C2B | 3 | `Sz:` | 噪声（3 字节偶然对齐），不计入名字表 |

→ 形式 A 是"逃生舱"：长度 ≥16 必须走它，所以全文件只有两条真名字。

## 4. 字符串形式 B：单字节 tag（占 99%）

```
1 字节 tag：  L    = tag >> 4      高 4 位 = 名字字节数（0..15）
              kind = tag & 0x0F    低 4 位 = 种类
随后紧跟恰好 L 字节 ASCII
```

### 4.1 怎么证明的（方向性检验）

把文件切成"可打印 ASCII 连续段"，对每段取**前一字节**当 tag，比较 `tag>>4` 与段长：

- 精确对齐（`tag>>4 == 段长`）：**273 条**
- 不对齐：**6,596 条**，全部是 `tag>>4 < 段长`
- `tag>>4 > 段长` 的情况：**0 条**

即 tag 只会"少说"不会"多说" —— 少说的原因很直观：名字后面常紧跟一个恰好可打印的字节（下一个字段的数值落在 0x20..0x7E），于是连续段被拉长（185/452 条属于这种 glue，如 `BattleFx` + `#`、`CastPlay` + `%`、`Evaluate` + `L`）。

只可能少的分布，加上 `tag&0x7F` 直方图里 `1→L8 / 17→L9 / 33→L10 / 49→L11` 的整齐步长，足以确认 `L=tag>>4`。

### 4.2 实测对照

| 偏移 | tag | L | kind | 名字 |
|---|---|---|---|---|
| 0x00004E | 0x81 | 8 | 1 | `BattleFx` |
| 0x000065 | 0x83 | 8 | 3 | `CastPlay` |
| 0x000090 | 0x87 | 8 | 7 | `Evaluate` |
| 0x0000E8 | 0xB3 | 11 | 3 | `SkillCamera` |
| 0x000167 | 0xB1 | 11 | 1 | `ChainEffect` |
| 0x0001CE | 0x91 | 9 | 1 | `ArrowNode` |
| 0x0002B5 | 0xB4 | 11 | 4 | `NormalZombi` |
| 0x0002CF | 0xE2 | 14 | 2 | `Heroes/Alchemy` |
| 0x00050F | 0x84 | 8 | 4 | `CthulhuF` |
| 0x001E51 | 0xC3 | 12 | 3 | `ECF/Behavior` |
| 0x000074 附近 | 0x74 | 7 | 4 | `Quatern`（L<8 → tag<0x80，公式不变） |

### 4.3 名字为什么"看起来被截断"

L 的硬上限是 15，所以表里出现：

```
NormalZombi (11)   BigHornShee (11)   CthulhuF (8)   Dichotom (8)
tterflam (8)       ungBeetl (8)       Salamand (8)   Unemploye (9)
```

反证一：`NormalZombie`、`BigHornSheep`、`Quaternion` 在全文件 **0 命中** —— 没有"截断后另存一份完整名"。

反证二（更关键）：有些被截的名字能明确补全，例如

| 存储形态 | 显然的完整名 | 长度 |
|---|---|---|
| `Pass/Entranc` | `Pass/Entrance` | 12 → 13 |
| `PassWeeklyTas` | `PassWeeklyTask` | 13 → 14 |
| `GoldCityArea` | `GoldCityArea9` | 12 → 13 |

即**索引里存的就是被切掉尾巴的前缀**，而不是"名字本来短"。可能的原因有两种，静态分不出来：

1. 引擎侧按前缀匹配（前缀唯一即可寻址）—— 索引只是给人看的辅助表；
2. 长名字走两段 token（第一段 L≤15 的头部 + 续段），但续段的 kind 语义没解开（见 §7）。

> 这条不影响"包里有哪些模块"的结论（前缀已足够识别），但**影响任何"按名字精确匹配"的自动化脚本**：拿索引去 grep 全名会漏。用的时候按前缀匹配。

### 4.4 统计

- 命中 **452 条 / 去重 451 条**
- 长度直方图：`L=7:1  8:146  9:100  10:75  11:46  12:40  13:24  14:20`（没有 L=15 的名字）
- kind 直方图（见 §5）
- 名字分布：0x0E..0x11000 密集（约 430 条），0x12000..0x19F67 稀疏（约 20 条）

---

## 5. kind 分布与语义倾向

| kind | 条数 | 代表名字（原文，含前缀被切的情况） | 观感 |
|---|---|---|---|
| 0 | 3 | `Pb/pgame.pbe`、`Src/Actor/Animation.luae`、`Sz:` | 形式 A 的长名 |
| 1 | 72 | `BattleFx`、`DoTwneer`、`ChainEffect`、`ArrowNode`、`DogElectric`、`HermitCrab` | 表现层/FX/节点 |
| 2 | 78 | `Heroes/Alchemy`、`BigHornShee`、`SipunculaZombi`、`_EternalPoiso` | 内容打包 |
| 3 | 58 | `CastPlay`、`SkillCamera`、`Dichotom`、`BackShoot`、`CareerBad` | 玩法行为 |
| 4 | 32 | `NormalZombi`、`GiantKil`、`RestartMiss`、`WxLuaPkgSchedu`、`Rule/RuleTi` | 规则/AI |
| 5 | 70 | `UnitNode`、`DataStruct`、`ECF/System`、`Reaction`、`Parallel` | 行为树/数据 |
| 6 | 52 | `GVG/GVGMap`、`PartyTim`、`RepeatBroadcas`、`AttackAndDodg` | 系统/网络 |
| 7 | 19 | `Evaluate`、`Infusion`、`Leonardo`、`Mechanic`、`HotSpring` | 逻辑判定 |
| 8 | 13 | `Unemploye`、`ExpandLan`、`Performanc`、`ObjectDisplay` | 展示 |
| 9 | 20 | `Goldhunt`、`MemoryLeakP`、`FindValidPosi`、`Accumulate` | 数值/寻路 |
| 10 | 12 | `NormalPetAI`、`Transform`、`RankOther`、`Mall/Mal` | AI/商城 |
| 11 | 13 | `Sound/BGM`、`SpawnAndBounce`、`ApplyButton`、`OpenEggMult` | 资源路径/UI |
| 12 | 2 | `GrowthFu`、`GymTitle` | 成长/称号 |
| 13 | 2 | `Foundation`、`DoubleCandy` | 活动 |
| 15 | 5 | `Scripts`、`BossTower`、`EquipTipRes`、`Rank/Gvg`、`SilverCoin` | 脚本/资源 |

注意：**kind 不是"文件类型"**。同一个 kind 里既有 `ECF/Behavior`（路径）也有 `GiantKil`（标识符），说明 kind 分的是**序列化角色**（如"可执行节点 / 资源引用 / 事件"），而不是名字长相。语义表没解开，故只给观测，不给断言。

---

## 6. 名字表产物

`notes/08-pkg-strings.txt`（451 行，三列 `偏移 / kind / 名字`），由 `scripts/08_parse_pkg_index.py` 直接生成：

```bash
py -3 scripts/08_parse_pkg_index.py unpack/assets/pgame.pkg.bin -o notes/08-pkg-strings.txt
```

脚本流程：`ascii_runs()` 切可打印段 → `scan_form_a()` 试 u32 长度外置 → `scan_form_b()` 以"名字前一字节"为锚套 `tag>>4`，**取恰好 L 字节**（不取整段，避免 glue 污染）→ 去重排序。

锚定这一步是全流程的关键：早期版本对每个偏移尝试 `tag>>4`，命中 5,143 条，但抽样全是名字内部错位（`b/pga`、`game.pb`、`rc/Ac`、`tor/An`），只能作废。

---

## 7. 仍未解开：名字之间的二进制字段

名字之间夹着这样的字节串：

```
17 24 00          23 00             48 00             1d 48 00
99 c8 18 00 00    99 40 01 00 00    99 08 03 00 00    （0x99 前缀 + u32）
70 d9 02 00       38 fa 02 00       78 fb 02 00       （递增的 u32，量级 0x2D8E0 起）
e0 d8 02 00 = 186,592                                （条目 1、2 后面都出现这个数）
90 00 00 00 = 144                                    （条目 2 的长度候选）
```

它们的形态显然也是 token（`L=0`、`kind` 承载 int8/int32/offset），但**非字符串 token 的 kind 语义表没有可证伪的证据来源**：尝试过全流步进（从 0x0E 按 `pos += 1+L` 走，19,963 步恰好收在 0x19F67 = EOF，但任何贪心变长码都能走到 EOF，不能作为证据），也尝试过按频次聚簇，都无法确定哪个 kind 对应 4 字节、哪个是 1 字节。

**按"事不过三"停止，理由不是难度而是价值**：

1. 这些字段最可能是 `pgame.pkg` 内的偏移/长度表；
2. `pgame.pkg` 本体是 8 字节分组加密（`docs/03`），拿到偏移也读不出明文；
3. 因此解出后对"通行证/金币能否本地伪造"的判断**零增量**。

如果后续拿到解密 key（`docs/05` §3 的 Lua dump 路线），正确顺序是：先用 §4 的 tag 律定位条目名 → 再用偏移读 pgame.pkg → 那时再来解 §7 才有意义。

---

## 8. 对"破解面"的影响

| 问题 | 本文件的证据 | 结论 |
|---|---|---|
| 包里有通行证/金币逻辑吗 | `xDPass`、`PassAsse`、`PassWeeklyTas`、`AGold`、`SilverCoinD`、`Goldhunt`（kind 15 `SilverCoin`、kind 9 `Goldhunt`） | 有模块，但**只是 Lua 模块名**，不含数值/配置 |
| 索引里有数值可直接改吗 | 451 条名字 + 未解字段；无任何明文字符串型数值 | 没有 |
| 改了索引能让游戏多发金币吗 | 索引只决定"从 pgame.pkg 哪里读哪段"；且 `InpackageFileHash.Android.jsonbin` 有完整性清单 | 不能 |
| 索引的真实用途 | 定位条目、看清模块划分 | 决定了动态路线该 dump 哪些 `.luae` |

→ 索引结构已"理干净到可用"：知道名字怎么编码、能列出 451 条、知道长名走哪条路。**它不构成一条伪造通道**，只是 `docs/04`/`docs/05` 的导航图。
