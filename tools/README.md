# tools/

分析用脚本。**本目录在发布包里是占位骨架**——请把你本地 `tools/` 下的真实脚本放进对应子目录后再发布。放入前请逐个检查：删除硬编码的本机绝对路径、设备地址（UDID/IP）、私有 token，改成参数或占位符。

## static/ — 静态分析（Python 3 + numpy + capstone 5.0.7）

| 脚本 | 用途 |
|---|---|
| `machopy.py` | Mach-O / 段节 / chained fixups 解析 |
| `objc.py` | ObjC 元数据解析（classlist / catlist / 相对方法表） |
| `armxref.py` | ARM64 交叉引用索引（ADRP+ADD/LDR 物化、BL/B 目标、寄存器生命周期感知扫描） |
| `graph.py` | 调用图构建 |
| `imports.py` | 导入符号与调用点 |
| `q.py` / `an.py` | 查询 / 分析辅助 |
| `keyscan.py` | 解密 key 扫描 |
| `hunt.py` / `probe.py` | 探针定位 |

> 运行前提：已有**合法获取、已脱壳**的主二进制。本仓库不提供二进制。

## dyn/ — Frida 只读观测

| 脚本 | 用途 |
|---|---|
| `driver.py` | spawn/attach 驱动（settle-then-attach、ObjC bridge 注入、`__CONFIG__` 注入） |
| `generic_check.js` | 地基自检（运行期字节 == 文件字节） |
| `trace_A2.js` | HMD 链 + 注入谓词 + CJPay 观测 |
| `deepA2.js` | 运行期函数指针扫描 + 探针调用观测 |
| `m6b.js` | statfs 黑名单命中统计 |
| `imgmark.js` | 逐镜像 `isEnvAbnormal`（延迟解析，无重入） |
| `decwatch.js` | 解密调用全量观测（含 roothide 区间判定） |
| `vmprobe.js` | 规则引擎 VM 原语计数 |
| `jbstate.js` | 越狱环境现状 + 明文内存扫描 |

> 纪律：全程只读，不修改返回值/字段；hook 回调内不做 ObjC 调用（放 `setTimeout`）。
> host/device 版本错位时必须用 `Module.getGlobalExportByName`。
