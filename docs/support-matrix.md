# GNU Linux x64 支持矩阵

矩阵的版本政策见 [versioning-policy](versioning-policy.md)。成熟度与验证等级是两个
独立字段；stable 不表示任意 Host/Mod/平台组合都已通过测试。

| 范围 | 成熟度 | 已有证据与实际边界 |
|---|---|---|
| ABI 1.0、2.0、2.1、2.2 | stable 入口 | 现有 P04/M02 等布局、拒绝、生命周期合同；按实际 H/Mod 字节记录 |
| A 预算 / B 审核 / C 并发 | stable capability | G02A/G02B/G03 各自有限入口；ABI 2.2 |
| H0 → H1 的 A、B、AB | stable SDK 入口 | G05 六组固定二进制配对；不得把 H0 或旧 H1 改名为另一个 H |
| ABI 2.3 四个 seam | experimental | G06 有限工具/流/CLI/TUI 套件；不是通用 provider 改写 |
| exact-host Hook | 单列 exact-host | G01 prepared slots 和明确形态，必须绑定 build ID/ELF/map |
| 当前 H 的 no-Mod、禁用重启、同进程 ABC | stable 入口 | [S02 R09](https://github.com/DSLZL/CM-build-linux-x64/actions/runs/42164580638) 的有限 GNU Linux x64 golden；精确字节、步骤与来源见运行工件 |
| 其他平台、任意 L4 Hook、完整父项目集成 | deferred | 没有本任务的运行证据 |

G05 已接受的配对证据来自 [R6](https://github.com/DSLZL/CM-build-linux-x64/actions/runs/41527027753)
和 [R7](https://github.com/DSLZL/CM-build-linux-x64/actions/runs/41528312220)；范围为 A/B/AB，
不外推到任意版本升级。G06 的 [R34](https://github.com/DSLZL/CM-build-linux-x64/actions/runs/41759600155)
保留原生执行和复用来源。其 legacy-abc 实际是 AC Core 与另一进程的 B TUI，
不能当成同进程 ABC 证据。

CM H 包含管理 CLI、RuntimePlan/native loader、ABI 服务与预制 slot，使用定制源码、
锁文件及配套 helper；它与官方上游制品的实现和字节不同。no-Mod golden 比较同一 CM H
在空集合及禁用后重启时的默认 provider/tool 行为，不声明与官方上游二进制相等。

## 当前资格记录

S02 consumer 产出五份 AC 报告及 `evidence/support-matrix.json`，格式见
[schema](../schemas/support-matrix.schema.json)。源码里不预填未来提交的“已通过”哈希。
矩阵每行记录 Host build ID/ELF/包清单、Mod 清单/版本/payload、ABI/capability/API/
target/CPU/glibc/依赖、实际命令与步骤、环境、报告 SHA/大小、执行来源和生产来源。
协议/state 限制保留在相应清单与哈希绑定的合同报告中。

当前 source/worker/run/attempt 是资格身份；复用的原 producer、历史执行步骤及大工件
ID/digest 各自保留。消费者重新核验原签名、清单、精确 checkpoint key 和审计，不能
通过更改 task 名称把 S01 生产记录改写成 S02。外层 receipt 为矩阵所在 consumer 工件
补齐本轮 artifact ID/digest；矩阵不能预知自身上传后的 ID，也不能自证来源。

有限 golden 包含同一 H 的无 Mod 和安装 A 后禁用的新进程；都执行受控 provider 与真实
builtin exec_command，对照完成状态、原工具次数和零 native Mod 回调。A/B/C 单项与 AB/AC
复用对应已通过步骤；新增 ABC 仅覆盖一个 Embedded TUI 进程的独立 Y 确认、预算
计数和 typed 并发策略请求，不宣称完整 Code Mode/全部后端组合已经集成。

升级使用 G05 固定 H0 → 当前 H1 的 A/B/AB、candidate/rollback/state-copy 和拒绝用例；
新增独占预算冲突在 native 初始化前拒绝。ABI major/minor、函数表、缺失能力、资源协议、
CPU/glibc/原生依赖、state owner/schema/version、exact-host 和篡改标签都保留独立失败证据。
不兼容不隐式编译、安装不执行构建脚本；运行集合在进程启动冻结，禁用需重启生效。

## 增量验证规则

仅资格测试的 Python 和政策数据不参与 native 编译身份。S01/S02/S03 的 task_id 使用同一生产路由；
required_checks 不参与编译，acceptance_script 按实际脚本内容入 key。相同脚本改路径
不会重建，改生产命令会失效。其他 task 仍保留区分，实际编译选项、工具链、Rust 输入、
环境和可达生产命令也保留。S02 与 S01 复用相同 native recipe，不忽略整个生产脚本。

每个测试按可达 Python、自己使用的政策记录、原生输入、环境和审计合同计算 checkpoint。
单用例失败只留下失败记录，不能缓存成 pass；已通过且匹配的无关步骤可继续复用。
共享逻辑变更影响其真实依赖步骤；汇总报告和矩阵每轮重生，旧报告不直接改名为新资格。
原大工件身份保持不变，只上传本轮轻量证据和新增检查点。

S03 的[二进制索引](mod-discovery.md)把来源验证、声明兼容和精确平台验证分开显示。
首次新增管理 CLI、索引 Rust 和编译依赖属于新的 Host 身份；后续单例 Python 或数据修订
按 31 个独立场景的真实依赖失效。当前签名、输入和审计仍每轮核验；后签资格及新的最小
消费步骤也必须真实执行。S03 [R10](https://github.com/DSLZL/CM-build-linux-x64/actions/runs/42355208453)
的六份验收报告及独立签名证明消费均通过；精确正例只覆盖 GNU Linux x64 的 SDK-A 选择与
Host SHA-256 `c45d3d141b50c9cc7cbc80991dd739c09144a3325eaef6b0a26a88dd628b01ec`。
Host、state、环境不匹配的已签名负例保持未验证，篡改资格被拒绝；ABI 2.3 仍为实验性。

S02 首轮 [R09](https://github.com/DSLZL/CM-build-linux-x64/actions/runs/42164580638) 的 362 项、五份验收报告、外层零构建审计及收据均已通过。
每轮增量复用结果以对应工件和收据为准；不承诺其他平台、native 沙箱、热卸载或 release-ready。


## 新平台首发范围

上述 x64 固定版本配对和运行证据继续保留。GNU Linux ARM64 目前是完整流水线候选，尚未取得产品资格；macOS/Windows 也不能继承 x64 的通过结果。

按用户决定，五个新增平台首发暂不验证历史旧版 Host 升级，不额外构建历史 CLI。历史升级、旧 Host 的 ABI/能力拒绝和跨版本 exact-host 绑定检查逐项 NOT_RUN；当前 H 的安装、组合、启停/禁用、状态/事务和身份拒绝仍须通过。运行报告包含 `qualification-scope.json` 和延期原因，`upgrade-h0-h1` 行只可为 declared，不能标记 platform-verified。具体用例边界见 [CI 说明](../ci/README.md#gnu-linux-arm64-candidate)。后续补充历史升级须使用对应平台真实原生旧版输入。
