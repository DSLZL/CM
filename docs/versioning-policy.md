# 运行时版本与兼容政策

本政策适用于当前 GNU Linux x64 支持线，不设未来维护年限。已发布的稳定 ABI、
capability 入口在该支持线内保留兼容调用方式；可以标注弃用，不能在原入口下删除、
改变布局或改义。破坏调用合同使用新 major 或新入口；破坏能力语义使用新的版本名。
ABI 2.3 和四个 G06 seam 仍为 experimental，有限测试通过不会自动升级其成熟度。

## 分开判断的版本

| 维度 | 判定依据 |
|---|---|
| Host/Mod 制品版本 | 区分交付物；SemVer 本身不证明二进制兼容 |
| Host API | 清单最低版本、实际提供的服务与 capability |
| ABI | major、协商后的 minor 视图、size、stride、对齐、保留字段与 callback |
| capability/section | 完整版本名、贡献类型、资源、协议及实际实现 |
| manifest/config | 各自 format/schema；不能从 ABI 版本推导 |
| 输入/输出协议 | 该 section 的 version、字段、大小及错误规则 |
| 状态 | scope 与 owner、文件 schema、Mod 状态版本；不自动迁移 |
| 平台 | target、CPU、glibc、原生依赖；只声明不等于已运行 |
| exact-host Hook | build ID、ELF、qualification map 和具体支持形态，另行校验 |

普通 SDK 按这些条件协商兼容，不要求所有 Mod 锁死单个 H 的哈希。资格证据始终绑定
实际 H/Mod 哈希。exact-host Hook 则必须额外匹配该 H 的 build ID、ELF 和 map；
未知 layout、inline、async、generic 或 detour 不能继承 SDK 的支持标签。

Host 保留 ABI 1.0、2.0、2.1、2.2 的对应入口/前缀。SDK 的
`Host::negotiate_version` 严格检查选中的 minor，不采用“Host minor 更大就直接读新表”
的规则；兼容旧表要先选择旧视图，再按其 size 读取。缺失 required capability 必须拒绝；
未请求的可选服务不能擅自调用。optional 服务也不能扩大已公布的必需条件或协议。

## section 库存

完整机器库存见 [policy.json](../fixtures/compatibility-policy/policy.json)。下表 size
为 GNU x64 C 布局的 HostApi/ModApi 最小字节数，来自对应 ABI 定义；其他 target
必须独立验证，不能直接搬用这些数字。

| ABI/入口 | size | section/capability | 合同 |
|---|---|---|---|
| 1.0 / cm_mod_entry_v1 | 32 / 72 | core.tool_parallel_eligibility.v1 | 同步 |
| 2.0 / cm_mod_entry_v2 | 56 / 64 | core.tool_parallel_eligibility.compose.v1 | 同步 Next |
| 2.1 / cm_mod_entry_v2 | 80 / 96 | core.exec_output_limit.v1 | 同步 Next |
| 2.2 / cm_mod_entry_v2 | 88 / 136 | runtime.lifecycle.v1、runtime.tool.v1、runtime.context_section.v1 | 请求运行时 |
| 2.2 / 同上 | 88 / 136 | core.turn_sampling_budget.v1、tui.submit_review.v1、core.turn_tool_concurrency.v1 | 请求运行时及各自策略协议 |
| 2.2 / 同上 | 88 / 136 | state.files.v1 | 文件状态 |
| 2.3 / cm_mod_entry_v2 | 96 / 136 | core.tool_continuation.v1、core.response_stream_observe.v1、cli.command.v1、tui.command.v1 | experimental 请求运行时 |

2.2 的 HostRuntime/ModRuntime/Request/Completion/Contribution 分别为 56/40/152/48/72
字节。2.3 continuation 服务为 48 字节，顶层及 continuation 版本是 2.3，内嵌
runtime/request/completion/contribution 仍是 2.2。不能把嵌套表一并改标签。
C 定义与 Rust 定义分别位于 [include](../crates/cm-abi/include/) 和
[cm-abi](../crates/cm-abi/src/)；实际 size、NULL、短表、保留字段与缓冲区由原生合同检查验证。

### 同步与同步 Next

入口描述表和函数指针在库驻留期间有效；Host 校验表后才初始化，错误缓冲区由调用者
分配，被调用者只在调用期间写入容量以内的字节。输入是有界借用，结果必须在归还前
复制到调用者提供的输出；禁止跨 Rust allocator 转移私有类型、trait object 或 Future。
init/userdata/release 归属各自 Mod，不能把另一 owner 的指针当成自己的对象。

1.0 policy 是同步调用，不具有 2.2 的异步 complete/cancel 服务。2.0/2.1 的 Next
只在该次同步调用内有效，至多调用一次；不得保存到后台线程、跨线程、归还后或另一
owner 使用。未调用可按已声明规则短路，已消费不可再次调用。确定性 DAG 顺序与独占
资源冲突沿用清单和对应 section 规则；metadata/plan 阶段不得执行 native init。
callback 错误、无效 Decision、输出越界与协议错误必须拒绝，不能悄悄继续默认路径。

### 请求运行时

Host 分配并拥有请求、thread/turn/scope 和 opaque handle；Mod 拥有自己的 userdata。
输入在普通 dispatch 内有界借用，SDK 保存的请求和后台数据必须复制；complete 同步
复制结果，Host state 服务复制键值。epoch/type/owner/parent/generation 均须有效。
handle 不能跨进程持久化，也不能转交给其他 Mod。普通 dispatch/cancel/request_release/
release 在每个 Mod 内串行，禁止普通入口重入；后台线程只用复制后的服务和自有数据。
Host 不持 metadata 锁调用 native 或 await。panic 必须留在 SDK 边界，abort/segfault
不能被此合同转成安全回滚。

Host 只投递首个终态。cancel 先终结 Host 结果再通知 Mod，晚 complete 仅可确认
quiescence，不复活结果；错误 owner 与本人取消保留不同错误。ordinary entry 返回、
quiescent 和子任务排空后才恰一次 request_release，全部请求释放后才 release userdata。
Future drop 走同一取消路径。非配合对象超时后报告失败并驻留到进程退出，不提前释放
活跃指针或热卸载库。进程退出本身不提供 native 内存安全沙箱。

输入/单状态值 64 KiB、结果 256 KiB、每 Mod 每 scope 1 MiB、64 个在途请求/Mod、
1024 请求/进程、4096 scope、128 项运行时贡献。协议版本、JSON 类型、深度、route
及资源按 section 校验。lifecycle/context 错误在真实 Core 边界锁存并阻止继续采样；
显式工具业务错误可返回模型，结构/状态/协议错误终止调用。

Mod 状态属于 registry；thread/turn 状态有独立生命周期。冷恢复/fork/child 新建
thread/turn，live resume 保留当前实例；隔离 registry 不继承可变状态。预算、发送审核、
并发策略仍分别遵守 [预算](turn-budget.md)、[审核](review-before-send.md)、
[并发](tool-concurrency.md) 的入口/取消/错误语义。审核统一独立 Y 确认，Enter/Tab 不确认。
2.3 保存 continuation、ACK 背压、UI owner 等附加合同见 [实验性 SDK](sdk-support.md)。

### 文件状态

state.files.v1 只在已声明 owner/schema/version 和受管理边界内操作文件；不把进程 handle
序列化成状态。文件状态可跨重启，内存 scope 不可。schema/owner/版本不兼容时拒绝
或走明确的迁移入口，不静默升级；复制、回滚、清理和 pending 状态仍依照
[状态合同](file-state.md)。卸载文件不意味着正在运行的 native 库已经热卸载。

## 支持标签与证据

成熟度 stable/experimental 与证据等级分开。declared 仅声明；planned 仅有计划；
compiled 仅证明编译；contract-tested 只覆盖指定合同；platform-verified 必须拥有同一
H/Mod 字节、目标/环境、实际通过的行为步骤、零构建审计和可追溯执行来源。
缺失、损坏、过期、身份不符的证据不得获得已验证标签。换 H、Mod、接口或环境不能
自动继承旧标签；历史记录保留原 source/worker/run/job/artifact/digest。

有限 golden、升级和禁用边界见 [支持矩阵](support-matrix.md)。完整父项目集成、未来维护
年限、其他平台、任意 Hook、热卸载和产品发布就绪不由本政策承诺。
