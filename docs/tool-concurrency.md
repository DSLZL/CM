# Turn 工具并发上限（示例 C）

G03 候选为 Linux x64 GNU Host 增加 `core.turn_tool_concurrency.v1`（Host API 0.9.0）。本页描述待独立 Actions 验收的实现契约；尚未发布合格的 C 工件。

安装预编译 `org.example.tool-concurrency` 后，重启 Host：

```sh
codex cm --home /path/to/profile install tool-concurrency.cmod
codex cm --home /path/to/profile launch -- --tool-concurrency 2
codex --tool-concurrency 2 exec 'your task'
```

也可在该 profile 的 `config.toml` 设置 `tool_concurrency = 2`。CLI 参数覆盖配置；App Server `turn/start` 的可选整数 `cmToolConcurrency` 覆盖本次新 turn 的默认值。有效范围是 1–1024；缺省或 `null` 继承配置，最终缺省保留上游并发行为。显式值需要已启用的 C，不能在缺少 provider 时静默忽略。

新 turn 冻结一次策略。`turn/steer` 省略或 `null` 继承活动 turn，传相同值可接纳；不同值在 Core 接纳锁内拒绝，输入不会入队，配置和活动策略也不变。修改配置、启停或移除 C 后须重启；移除 C 前应清除残留的显式配置。

| 路径 | 范围 |
| --- | --- |
| Embedded TUI、exec、stdio App Server | 接入同一 Core turn 的 typed 参数 |
| 经 `ToolCallRuntime` 的直接工具，包括 MCP/dynamic | 每个实际 turn 共享容量 |
| Code Mode `exec` / `wait` | 仅编排，不占 leaf permit |
| Code Mode 到真实工具的叶子、多 cell / runtime | 使用原 turn，同享容量 |
| 绕过 `ToolCallRuntime` 的 hook MCP、其他进程 | 不覆盖 |
| 远端、旧或错误身份 backend | 显式请求在业务前拒绝 |

原有工具并行资格和每个 runtime 的读写锁继续生效，因此 N 是上限，不保证所有工具都能同时执行。C 不开放 exec 自调用，也不自动把旧 cell 绑定到新 turn。

许可同时覆盖实际执行、取消收尾及结果交接。native Mod 已返回 terminal 但尚未 quiet 时继续持有许可；旧 scope 关闭后不再接纳叶子，并唤醒等待者。策略初始化失败在本 turn 内不可重试。

C 只依赖 SDK，使用既有 C ABI 2.2。事件 14 的请求为 `{"version":1,"requested_limit":N}`，回复为 `{"version":1,"limit":N}`，N 可为 `null`。Host 检查版本、字段、范围和与冻结请求的一致性；计数器、semaphore 和许可归 Host 管理，不跨 ABI 传 Rust 对象。全局资源只允许一个 C provider，冲突在加载 native 代码前拒绝。

同一冻结 H 支持 C 单独安装、禁用、移除和与已接受原 A 同时加载。父任务将另行验证原 A+B+C；G03 交付原 C 的 payload、manifest、archive 和作者身份，不声称父任务已通过。

验收仅在独立 `DSLZL/CM-build-linux-x64` 的 hosted Ubuntu 24.04 X64 中执行。七个 G03 检查点分别保留日志和执行来源；Python 单项修复按依赖闭包失效，生产输入相同则复用 H 和大工件。协议 TypeScript/JSON、压缩 exports 与 config schema 在 worker 封存 H 前由固定上游生成器更新并检查；不在本地生成或编译。

Code Mode 的正常 V8 解释器保留默认运行方式。审计核对封存 helper 摘要、实际 exec、PID/线程父链、transport 和业务 cell；仅将该进程族的执行内存记为 `normal_business_interpreter`。Host、Mod 及无法归属的执行内存仍失败；存在正常 V8 JIT 时不宣称全进程零 JIT。安装、加载和组合过程仍禁止编译或 JIT。
