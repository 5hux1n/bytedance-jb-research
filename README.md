# 字节系 App 越狱/注入检测机制逆向研究

> iOS 平台上番茄小说、红果短剧、抖音三款字节跳动 App 的越狱检测、注入检测与设备风控机制的逆向分析。静态（Capstone + 自写 ObjC/交叉引用索引 + 离线批量解密）+ 动态（Frida 只读观测）+ 第三方交叉验证（IDA Pro 9.3 Hex-Rays）联合完成。

## ⚠️ 免责声明

本仓库是一次**合法安全研究**的记录，仅供防御研究、学术交流与安全教育参考。

- **全程 Frida 只读**：仅 `onEnter/onLeave` 读参数、读返回、backtrace、dump 内存，**未修改任何目标 App 的返回值、字段或行为**。
- 本仓库**不包含**任何 IPA、脱壳后的 Mach-O、可直接运行的越狱/绕过代码，也不提供样本获取途径。复现需读者自备**合法获取**的样本。
- 所有技术论断均以目标二进制中实际读出的指令、字符串、表结构与设备现场读数为依据；无法取得直接证据的判断已在报告中明确标注为"不可验证"。
- 请勿将本研究用于规避厂商安全机制、破坏业务完整性或任何违反相关法律法规与服务条款的用途。使用者自负其责。

##博客地址

https://shuxin.my/p/169bc8e7-6f96-4644-b850-8da8e8549007


## 分析对象与环境

| 项 | 值 |
|---|---|
| 番茄小说 | 7.4.1（`com.dragon.read` / 主二进制 `Reading`） |
| 红果短剧 | 7.4.1（`com.phoenix.video` / 主二进制 `Eggplant`） |
| 抖音 | 40.8.0（`com.ss.iphone.ugc.Aweme` / 主二进制 `AwemeCore`） |
| 设备 | iPhone 11 Pro Max（`iPhone12,5`），iOS 26.0，roothide（relaxin） |
| Frida | host 17.7.3 ↔ device 17.23.3 |

## 方法论

- **静态**：`otool` 解析段节/导入符号；自写 ObjC 元数据解析器（`__objc_classlist` / 相对方法表 / chained fixups）；自写 numpy 交叉引用索引（ADRP+ADD/LDR 物化、BL/B 目标、寄存器生命周期感知扫描）；Capstone 5.0.7 反汇编；还原解密算法后离线批量解密整个字符串池。
- **动态**：Frida 只读 hook（`spawn → resume → 等 2~4 s → attach`，解析全部放 `setTimeout` 避免重入死锁），观测调用链 backtrace、探针命中、解密调用、规则引擎 VM 原语计数。
- **交叉验证**：IDA Pro 9.3 + idalib，对 508 MB 主二进制采用「雕刻子二进制」法（按目标函数取窗口包成最小 ELF64，`run_auto_analysis=False` 逐函数 Hex-Rays），独立复核手工逆向结论。

## 核心发现 TL;DR

1. **三款 App 共用一套安全组件**：运行期符号名表 15/15 逐字节同一（番茄↔红果偏移恒定 `0x41DF00`），规则引擎 VM 原语逐字节同构，差别只在规则配置规模（番茄/红果 15 条、抖音 66 条）。

2. **真实检测面比"代码里写了多少检测"窄得多**：`fopen` 五探针是死代码（静态零引用 + 内存零登记 + 运行时零调用）；`statfs` 93 路径在 roothide 上全 miss；`canOpenCydia` 因未声明 scheme 恒假；文件遍历链需支付页才跑而本机无此入口。本地唯一给出非零结论的只有 `/hmd_tmp_file` 越界写（→ `is_env_abnormal=1`）与一次目录名巧合命中。

3. **检测挂在 HMD（Heimdallr）上报链上**，每次构造上报 header 时触发（三条并列路径），结果用 `dispatch_once` 缓存；越狱标志进入 HMD 的**明文字典**（34 字段，含 `is_env_abnormal`）。

4. **SafeGuard 规则引擎在本构建中不可达**：六路引用全 0、不在静态构造表、运行期零调用，但模块初始化确实发生过（沙盒目录存在）。规则数据里含 roothide 特征串，却没有任何可达路径会解密它们。

5. **加密名单其实覆盖三代越狱**（Dopamine/roothide/Xina），但以 bundle-id 与 plist 名出现，不是路径与库名——这正是此前只做路径扫描看不到的原因。

## 仓库导航与建议阅读顺序

```
README.md                          ← 当前文件，总览
article/技术博客文章.md             ← 面向读者的叙事版，建议先读
reports/
    深化分析总报告.md               ← 结论与证据的主报告
    发现记录.md                     ← 逐轮原始发现过程（最详细）
    静态分析指导文档.md             ← 方法论与静态搜索 checklist
artifacts/                         ← 派生数据（无任何二进制）
    hexrays_f5.md                  ← 11 个关键函数的 IDA Hex-Rays 反编译文本
    符号名表_15条.csv               ← 共用组件证据（§2.1）
    规则引擎对照.csv                ← 三款 VM 对照（§2.2）
    解密字符串池_越狱相关19条.csv    ← 全池批解的越狱命中子集（§6.3）
    平坦化地图.csv                  ← 控制流平坦化统计（§6.4）
tools/
    static/                        ← 静态分析脚本
    dyn/                           ← Frida 只读观测脚本
```

建议顺序：**README → 博客 → 深化分析总报告 → 发现记录 → artifacts/tools**。

## 复现说明

- `tools/static/` 下的脚本在**已有合法获取、已脱壳的主二进制**前提下运行，依赖 Python 3 + numpy + capstone(5.0.7)。本仓库不提供二进制，请读者自备。
- `tools/dyn/` 下为 Frida 只读脚本，运行环境见上表（注意 host/device 版本错位需用 `Module.getGlobalExportByName`）。
- 全量解密字符串池（11,812 条）未公开，`artifacts/` 仅收录越狱/注入相关的 19 条命中子集，以避免无关路径/标识符泄露。

## 待核对

> 整理过程中若发现报告之间的数字有出入，列于此处，不自行"修正"，留待原作者核对。
>
- `artifacts/规则引擎对照.csv` 第 4 行（抖音）为 9 个字段，表头与其余两行为 8 个字段——末列"VM 原语与番茄逐字节同构"与"规则规模更大"挤在同一行，属排版问题，不影响任何数字与结论。
- 三份文档中出现的"1118 次"与"1117 次"指两个不同对象：前者是注入谓词 `pred_inject_substr` 的调用次数，后者是 `-[HMDCrashBinaryImage isEnvAbnormal]` 的读取次数；并列出现时易被误读为矛盾。

## License

- 代码（`tools/`）：MIT License，见 `LICENSE`。
- 文档与数据（`reports/`、`article/`、`artifacts/`）：CC BY 4.0，见 `LICENSE-docs`。
