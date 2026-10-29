# Runtime turn 主采样预算

CM-G02A 当前是待 Actions 验证的候选，原六项验收均为 `not_run`。
示例 Mod 为 `org.example.turn-budget`，源码在 `examples/mods/turn-budget`。
它单独编译为预制 `.cmod`，用户安装、启用、禁用及移除均使用现有 Host H。

## 配置与使用

需要声明 `core.turn_sampling_budget.v1` 的 Host API 0.7.0，以及 ABI 2.2。
候选 H 的 release ID 为 `cm-host-0.9.0-g02a`。先核对独立 worker 的实际
source、run/attempt、工件摘要及验收回执，再使用对应的预制 H/A。
缺 API/capability 的旧 H 会在 native 加载前拒绝，不会自动升级或编译。

安装到独立 home 后，在该 home 的 `cm-runtime.toml` 合并以下配置，保留其他 Mod
和已有配置。缺少 `policy` 时不限制采样。

```toml
format_version = 2

[mods."org.example.turn-budget".policy]
max_main_samples = 2
session_sources = ["cli", "vscode", "exec"]
request_kinds = ["turn"]
```

`max_main_samples` 必须为 1 至 4294967295 的整数。来源只能从 `cli`、`vscode`、
`exec` 中显式选择；类别目前只支持 `turn`。数组非空且不得重复，未知字段、标签、
负数、零和溢出值均拒绝。配置仍使用既有默认值、profile、用户配置及本次覆盖的合并规则。

```sh
/opt/cm/bin/codex cm --home /srv/cm-profile install /downloads/turn-budget.cmod
# 保存 cm-runtime.toml 的配置后，显式更新锁。
/opt/cm/bin/codex cm --home /srv/cm-profile lock
/opt/cm/bin/codex cm --home /srv/cm-profile launch -- exec "Complete this task"
/opt/cm/bin/codex cm --home /srv/cm-profile disable org.example.turn-budget
/opt/cm/bin/codex cm --home /srv/cm-profile launch -- exec "Continue with the default behavior"
/opt/cm/bin/codex cm --home /srv/cm-profile enable org.example.turn-budget
/opt/cm/bin/codex cm --home /srv/cm-profile remove org.example.turn-budget
```

启停和配置改变在下次启动生效，当前进程使用启动时冻结的集合。只允许一个预算
provider；第二个预算贡献会以 `exclusive_conflict` 在加载前拒绝，保留原成功 profile。
禁用/移除恢复默认行为，保留用户数据和原 H/A 字节。

## 名额和结束行为

一次主逻辑模型请求扣一个名额。同一请求内部的 HTTP/流重试不额外扣费。
compaction、review、title 及未声明来源不在本策略内。额度按实际 runtime turn
保存；pending input、Stop continuation、模型切换和 step/client 重建沿用同一额度。
并发 admission 通过 Host 的同一原子检查，不能超过 N；已开始的请求失败或取消不退费。

第 N+1 次主请求在调用 provider 前返回 `sampling_budget_exhausted`，通过宿主既有
错误流程结束 turn：一次错误及一次失败完成。外层不会靠重新采样或 Stop continuation
清零；未消费输入、完成工具结果及历史按宿主规则保留。取消继续使用真实取消原因，
等待 native 请求 quiet 后释放，原生库保持到进程退出。

新的实际 turn、thread 或独立 registry 使用新额度。文本 turn ID 相同不能代表同一个
runtime scope。普通 resume/fork 后开始的新 turn 也有新额度；未完成 turn 的旧额度
不支持跨进程/worker 持久恢复。显式要求该恢复的低层入口返回
`sampling_budget_recovery_unsupported`，不能把新额度当作旧额度恢复。

## SDK 与验证边界

贡献固定为 `kind="sampling_budget"`、`capability=resource="core.turn_sampling_budget.v1"`。
这是独占的全局预算资源，不使用普通工具的 `<owner>__name` 命名空间。
ABI 2.2 的布局不变，新增 kind 9 / event 12。Host 在真实 turn scope 首次 admission
发送 `{"request_kind":"turn","policy_version":1}`，A 返回 JSON policy 或 `null`。
结果经 Host 验证后冻结，计数始终由 Host 持有。其他普通 runtime 贡献沿用原合同。

Actions 将六个场景分别执行、审计并保存成功检查点：counting、reentry、terminal、
scope、cancellation-recovery、plug-and-play。最后一个失败仍保存前面通过项；测试
代码修正仅失效依赖受影响的检查点。生产输入和 runner 环境不变时复用既有 producer
及原大工件，当前验证 overlay、隔离探针和回执仍执行。

内部模型切换、step 重建、同文本 ID、并发 scope 等由独立私有 Core 测试二进制验证，
与打包 CLI H 分列；它复用 M02 已编译的同一私有测试二进制。业务/provider、Stop、
终态、取消、恢复及安装效果使用实际预制 H。旧 H 的真实安装拒绝用例使用经原回执
和工件摘要绑定的 M05 API 0.6.0 二进制，仅执行 metadata 安装；过期或不可用工件
明确阻塞，无重编译替代。

全部编译、格式、Clippy、测试和运行实验只在独立 hosted Linux x64 GNU Actions。
完整 Core/TUI suite、其他平台、跨进程旧预算恢复及发布就绪状态不由本候选证明。
