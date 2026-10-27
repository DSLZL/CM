# 原生运行时 SDK（ABI 2.2）

本增量已通过独立 Linux x64 [M02 验收](https://github.com/DSLZL/CM-build-linux-x64/actions/runs/40514837331)（源码 `825c11e`）。
当前支持面为本地 Embedded
`codex exec` 的新建、resume、fork，以及本地 stdio App Server。
TUI、Remote、WebSocket、daemon 和任意 Core 私有接口不在本次支持面。

`cm-sdk` 只依赖 `cm-abi`。Mod 在自己的 Cargo workspace 内编译为 cdylib，
Host 不链接具体 Mod。`fixtures/mods/lifecycle-audit` 和 `example-tool` 是独立作者示例；
共享测试实现位于 `fixtures/runtime-sdk/fixture.rs`。

## 清单与入口

使用 format 3 的 `mod.toml`，`binary.entry = "cm_mod_entry_v2"`，ABI 范围固定为
2.2，Host API 下限为 0.5.0。三个可声明 capability 与贡献类型为：

| capability | kind | 运行时内容 |
|---|---|---|
| `runtime.lifecycle.v1` | `lifecycle` | thread/turn 的开始、就绪、恢复、空闲和结束通知 |
| `runtime.tool.v1` | `tool` | 接收 JSON object，返回 JSON 值的普通模型工具 |
| `runtime.context_section.v1` | `context_section` | 在模型请求前渲染 UTF-8 上下文 section |

资源名必须为 `<Mod ID>__<局部名称>`，仅含 ASCII 小写字母、数字、`_`、`-`，
总长最多 64 字节。因此包含点号的 Mod ID 当前不能声明这三种运行时贡献。
名称、kind、capability、贡献 ID 必须与二进制入口的描述表完全一致。
每个 route 非零且在该 Mod 内唯一。运行时贡献不接受 priority 或 order 边。
同类名称冲突、未声明名称和保留名称在注册及模型请求前失败。

作者为自己的类型实现 `cm_sdk::Mod`，通过 `export_mod!` 提供入口和不可变描述表。
`dispatch` 收到的是 Mod 内部拥有的请求副本；Host 不持有该类型，也不接收 Rust
trait object、Future、Waker、闭包或 allocator 所有权。C 定义见
`crates/cm-abi/include/cm_mod_v22.h`。ABI 1、2.0、2.1 保留原前缀及行为。

## 状态与异步完成

请求携带 opaque 的 request、Mod、thread、turn handle。Host 复制
`Host::state` / `set_state` 的键值；Mod 只能使用该请求所属的三个状态 scope。
Host 校验进程 epoch、slot generation、类型、所有者、父 scope 和请求状态。
handle 不可持久化为跨进程状态，也不能转交给其他 Mod 或新 turn。

同一 registry 的普通线程共享其 Mod 状态，各自拥有新的 thread/turn 状态。
正常冷恢复、fork、本地 child 新建 thread/turn 状态；live resume 保留当前实例。
隔离会话默认使用上游空 registry；显式创建并提供 CM registry 时建立独立 Mod 状态。
CM holder 只放入真实 `ExtensionData`，不把可变状态放入可继承的 Init seed。

`Host::complete(request, status, result, quiescent)` 同步复制结果。
Host 只投递第一个终态。`quiescent=true` 是作者的承诺：以后不再访问该请求和
scope。取消首先终结 Host 结果，再通知 Mod；重复完成或取消后的完成可确认
quiescence，但不能再次投递。作者仍须最终确认 quiescence。

每个 Mod 的普通 dispatch、cancel、request_release 与 release 串行执行。
后台线程可以使用复制后的 Host 服务和自己拥有的数据；普通 native 回调禁止重入。
Host 不在 metadata 锁内调用 native 代码或 await。
Host 等待 dispatch/cancel 返回且 quiescent 后，恰好一次调用 request_release；
只有全部请求释放后才调用 Mod userdata 的 release。

Future 被丢弃也会进入 Host 取消与清理路径。非配合回调不会通过提前释放或卸载库
来终止：请求 30 秒超时，清理等待上限 5 秒；超时报告失败，并将请求、状态、userdata
及库保留到进程退出。原生 Mod 与 Host 同进程运行，这不是内存安全沙箱。

## 上限与失败传播

请求输入及单个状态值最多 64 KiB，结果最多 256 KiB；每个 Mod 的每个 scope
状态总量最多 1 MiB，含键长度。每个 Mod 最多 64 个在途请求，进程最多 1024 个请求、
4096 个 scope、128 项运行时贡献。JSON 深度最多 16，工具输入必须为 object。

生命周期和 context contributor 的上游接口没有 Result 返回值，adapter 会锁存错误；
Core 在 thread 发布、turn 启动、工具执行和模型请求前检查。必须成功的回调失败不能
通过空结果继续采样。工具显式业务错误可返回模型，协议/状态错误终止真实调用。

运行中的集合在进程启动时冻结。修改或移除 profile 内的 Mod 不热切换当前进程；
正常退出并以相同 Host H 重启后才使用新集合。不会热卸载活跃原生库。

## 验收边界

构建、fmt、clippy、测试和实验只在独立 hosted Linux x64 Actions 执行。
生产者先冻结 Host，再独立构建两个 Mod 和反例变体。消费者无源码 checkout、无缓存
权限、无编译器，只使用冻结制品运行真实 CLI、受控 provider 和同步屏障。

私有 child/isolation 分支另由真实上游 ThreadManager 的原生集成测试验证。
该测试可执行文件单独记录 SHA，不冒充打包 CLI 的 H。所有报告保留失败证据，
M02 通过不表示完整 Core suite、其他平台或产品发布就绪。
