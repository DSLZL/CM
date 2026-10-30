# 发送前审核（CM-G02B，待独立验收）

`org.example.review-before-send` 是独立编译的原生 Mod B。安装后在本地 Embedded
TUI 中，第一次正常提交只展示审核面板；按 **Y** 才提交一次，**Esc** 返回编辑。
Enter、Tab、按键 Release 和长按 Repeat 都不确认。审核准备期间按 Y 也不会确认。
自定义提交键仍按当前 keymap 触发审核；Y 与提交、队列或全局快捷键冲突时须先改键。

面板显示展开粘贴后的完整文本、附件和引用，支持上下滚动。首次提交和 Esc 不消耗
原编辑器、元素 ID、附件、粘贴、引用和历史状态。修改内容、光标、附件、目标会话、
模型或提交意图后需要重新审核。审核本地图片时保存已编码的图片字节，Y 确认再次校验
源文件内容；最终发送被冻结的字节，失败保留草稿。
消息身份保留展开后的精确文本，包括有意义的首尾空白；粘贴占位符遵循正式队列的
展开顺序，不用统一 trim 掩盖已审核输入的变化。

运行中的队列/steer 先审核入队输入，界面会提示最终请求的上下文可能随后变化。
队列、图片准备及 steer 回调共享一次发送门闩；明确拒绝且未改动的 steer 可领取一次
后续重试。合并、恢复或改变内容身份的重编号和修改须回到编辑器重新审核。QuestionAnswer
保留现有问答语义。程序生成的普通 prompt 在清屏、改模式或入队前拒绝；明确审核过的
`/init` 仅允许其固定派生 prompt 继承一次授权。

启动确认只保留提交意图，等真实 Embedded 桥接和会话就绪后仍需审核和 Y。
CLI 初始 prompt 也进入草稿，已有草稿不会被覆盖。B 不支持 exec、stdio、远程或
其他 TUI 后端；这些路径在原生入口、业务及连接前拒绝。停用或移除 B 后恢复原行为。

## 原生契约

清单 format 3，Host API 最低 `0.8.0`，ABI 仍是 `2.2`。
capability/resource 均为 `tui.submit_review.v1`，kind `submit_review`（10），
event `SUBMIT_REVIEW`（13）。资源独占，不使用 `<owner>__name` 命名。
没有新增或改变 ABI 结构布局、尺寸或 stride。

请求属于显式 UI owner，含真实 Mod scope，thread/turn scope 为 NONE，三个 Core ID
为空。Core adapter 不接收 UI 贡献。复用现有有界请求表、串行 worker、取消、完成、
quiescence 和 request_release；UI 只能访问本请求的 Mod 状态。协议/超时错误锁存，
不能通过建立新的 UI actor 自动放行。

输入为严格 JSON：schema_version=1、actor、review_id、edit_version、origin、intent、
content_sha256、text_bytes、attachments、mentions、preview、preview_truncated。
intent 为 send/queue/command；preview 最多 8192 UTF-8 字节，总输入最多 64 KiB。
完整快照和发送权只归 Host。B 唯一成功结果为：

```json
{"schema_version":1,"require_review":true}
```

多余字段、错误版本、false、错误类型或畸形 JSON 均失败。此结果只要求审核；
原生 Mod 无法通过结果授权提交。B 没有配置项，独立 Cargo workspace 仅使用 SDK/ABI
及 JSON 依赖；其 payload 不链接 Codex Core 或 Host adapter。

## 验收和重试

六阶段分别为 nondestructive、invalidation、key-events、entry-coverage、queue-lifecycle、
plug-and-play。实际打包 H 通过 PTY、受控 provider 和 Worktrees MCP 验证；私有草稿、
队列和协议边界由单独构建、摘要绑定的 TUI 测试可执行文件验证，后者不冒充产品 H。
固定异常 Mod 覆盖非法结果、错误、panic、重复/过期/延迟回调、取消及超时。

生产者冻结 H 后才独立构建 B。A 使用已验收 payload 原样回归，不重新编译。
探针有独立编译缓存；仅改 Python 驱动或自检时复用 H、B、探针和大输入工件。
每个验收阶段按 AST 依赖计算检查点，失败阶段独立重跑；共享依赖变化使对应检查点失效。
当前 rootfs、命名空间隔离、外部执行/网络审计、API 与来源收据每轮仍重新验证。
消费者无源码、编译器、Cargo lock、构建缓存或 CI 服务凭据，进度每 30 秒输出。

当前仅完成本地源码准备，六项验收保持 NOT_RUN；构建、格式、clippy 和运行测试
须在独立 hosted ubuntu-24.04 X64 GNU Actions 执行。本文件不表示发布就绪。
