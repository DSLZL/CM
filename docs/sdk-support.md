# 实验性 SDK 接入面（CM-G06 候选）

本文描述 Host API `0.11.0` / ABI `2.3` 的候选实现。七项 G06 验收均为
`not_run`；当前没有通过编译、原生回归或独立 Actions 验收的结论。
原有 [ABI 2.2 SDK](runtime-sdk.md) 与作者模板继续使用原来的导出和协商接口。

## 能力和版本

| capability | contribution kind | 有限接入面 |
|---|---|---|
| `core.tool_continuation.v1` | `tool_around` / `tool_replacement` | 默认 namespace 下真实 builtin `exec_command` |
| `core.response_stream_observe.v1` | `response_stream` | 主采样响应事件的有界 metadata 与逐项 ACK |
| `cli.command.v1` | `cli_command` | `codex cm run <声明的命令> [INPUT]` |
| `tui.command.v1` | `tui_command` | 当前 Embedded TUI owner 显示一条有界 notice |

作者使用 format 3 清单，ABI 范围固定为 `2.3`、Host API 下限为 `0.11.0`，
入口仍为 `cm_mod_entry_v2`。使用 `cm_sdk::export_sdk_mod!` 和
`Host::negotiate_sdk`；旧 `export_mod!` / `negotiate` 仍严格协商 2.2。
新 Host 顶层表和 continuation 服务标为 2.3，内嵌 runtime、request、completion、
contribution DTO 保持 2.2。C 定义见 `crates/cm-abi/include/cm_mod_v23.h`。
短表、未知版本、空 callback、保留字段和不完整能力声明必须失败。
每个 Mod 的 required_capabilities 继续沿用最多 8 项的集合上限。

## 保存的工具 continuation

Host 保存 registry 已选中的 handler、owned invocation 和 call state，原工具
结果也留在 Host。Mod 不接收 Rust Future、闭包、对象、allocator 或可重路由的名字。
本候选只允许 `exec_command`，沿用原 approval、sandbox、pre/post hook 和并发管理。

`tool_around` 贡献以目标资源建立独立 DAG，稳定 ID 解决无先后关系的顺序。
缺失/跨 phase 的引用和环失败。`tool_replacement` 独占目标；两个 replacement
或 replacement 与 around 混用时，在 native 初始化前报出双方所有者。

每个调用收到 `{"version":1,"target":"exec_command","arguments":{...}}`：

- `next_start(request)` 只消费一次保存的下游，返回 opaque task handle。
- `next_poll(request, task)` 不阻塞，返回 Pending 或成功/失败/取消的有界副本；
  重复 poll 不消费结果，容量不足也不消费，调用者的指针与容量不可被替换。
- `next_cancel` 通知原取消 token；`next_release` 立即使 task 不可再使用，并在
  已运行工作排空后才回收实体。

下游 native dispatch 等当前普通 dispatch 返回后才运行，避免普通入口重入。
预览 JSON 含 version、success、text、truncated，text 最多 16 KiB。
最终 decision 是 `{"action":"keep","version":1}`（必须已有完成的 next），
`{"action":"text","version":1,"text":"...","success":true}`，或
`{"action":"error","version":1,"message":"..."}`。text/message 最多 64 KiB。
零次 next 可短路；重复消费、错误 owner、陈旧 generation 和协议错误不得静默放行。
不提供改写原调用参数或任意工具 handler 的能力。

请求终态、取消、晚完成、ordinary entry 归还、QUIESCENT 和子任务排空共用既有
runtime。取消后的完成只能确认 quiescence，不能复活结果；本人取消和外来 owner
错误保留不同状态码。request_release 在全部条件满足后恰一次调用。
非配合 Mod 沿用失败与保留至进程退出的策略，不能提前释放活跃 userdata 或卸载库。

## 响应流 metadata 与背压

实际主采样调用绑定 turn level、逻辑 request ID 和 transport attempt。
HTTP、WebSocket 和 fallback 共用该逻辑身份；这不表示所有这些后端已获产品资格。
观察者识别 created、completed、工具 item/delta/done、文本字节数、opaque、error
和 stream_end，不向 Mod 暴露原流对象，也不接受替换或追加 provider event。
标识符最多 512 字节，输入包含 version、request_id、attempt、sequence、event。

每拉取一项，按已提交 DAG 等待各 Mod 返回精确
`{"version":1,"ack":<sequence>}`，再透传原事件。无预取队列；消费者暂停时不会
继续拉取上游，消费者 drop 会取消待完成 native 请求并释放原流。
缺少 completed 的干净 EOF、错误 ACK、未知字段或版本必须失败。
当前支持声明仅为 metadata 观察与背压，不包含任意 provider 改写或通用流 SDK。

## 同一命令图与 UI owner

清单增加 `commands = { version = 1, entries = [...] }`。每个 entry 具有
id、name、help、input（none/optional/required）、section（cli/tui）和非零 route；
其 id/kind/resource 必须匹配 contribution，实际 native route 在 init 前再核对。
命令名为 `<Mod ID>__<局部名称>`，只含小写 ASCII、数字、`_`、`-`，总长最多
64 字节；当前含点号的 Mod ID 不能声明命令。每个 Mod 最多 32 项，help 最多
256 字节且无控制字符，动态 builtin/service tier 重名必须失败。

Clap parse、help 和各 shell completion 使用同一不可变 metadata graph。
帮助、补全与 metadata 命令不执行 constructor/entry/init；实际运行再次校验 profile、
plan 和声明。CLI 接受至多一个 UTF-8 INPUT（8192 字节），native 输入为
`{"version":1,"input":null}` 或字符串，输出为 `{"version":1,"text":"..."}`，
text 最多 64 KiB。CLI/TUI 请求不伪造 Core thread/turn/call 身份。

TUI slash 搜索、解析、审核和 dispatch 共享命令身份。native 只返回
`{"version":1,"notice":"..."}`，notice 最多 8192 字节，除换行/Tab 外不允许
控制字符。后台完成必须交回创建请求的实际 UI 线程，由活跃 owner 和 pending ID
校验并消费一次后显示。关闭、重连或 owner 更换后不得应用过期 notice。
已有发送前审核继续统一按 Y 确认，Enter/Tab 不确认。

## 构建和证据边界

两个独立作者 workspace 只依赖 cm-sdk/cm-abi，各有 v1、v2、replacement 变体。
先冻结生产 Host H，再构建作者 payload；同一 H 用于组合、禁用、删除与重启更新。
C ABI probe 与私有 Core/UI probe 各自记录身份，不能冒充打包 CLI。
现有 ABI 2.2 A/B/C 单项兼容检查不代替父任务的完整集成验收。

编译、fmt、Clippy、测试和所有产品执行只在独立 Linux x64 worker 运行。
消费者仅接收冻结工件，在无源码 checkout、无缓存权限和无编译器的 rootfs 内执行。
原七份报告保留生产者/消费者、source/worker/run/attempt/job/artifact 以及 H、Mod、
probe 的实际哈希与失败记录。源码 CI、静态补丁校对或单个 probe 通过均不是验收。
其他平台、任意 provider 改写、内存安全沙箱、热卸载及产品发布就绪均未获此候选证明。
