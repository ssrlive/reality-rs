# REALITY Protocol Notes

这份文档整理了本仓库里 REALITY 相关实现的目标、数据流、配置映射、实现边界和实际风险。

读者对象分成两类：

* 非专业读者：想知道 REALITY 大概在解决什么问题，现在这套代码到底能做什么。
* 技术读者：想知道这套实现怎样接进 Rustls、数据怎么流、和 Xray 的 REALITY 到底差在哪。

本文描述的是当前仓库中的实现状态，不是假设中的理想版本。

## 一句话结论

当前这套代码已经实现了一个“基于 Rustls 的、可运行的、带配置和分流能力的 REALITY 原型服务端”，但它仍然是 example-level integration，而不是完整的 Xray 级生产实现。

## 给非专业读者的 5 分钟版本

### REALITY 在做什么

可以把 REALITY 粗略理解成：

* 连接表面上仍然长得像正常的 TLS 1.3 连接。
* 客户端和服务端在 TLS 握手很早的时候，用一个双方约定的隐藏规则，判断“这是不是自己人”。
* 如果是自己人，就继续走真正的代理链路。
* 如果不像自己人，就把流量转去一个诱饵站点，或者按普通探测流量处理。

它的目标不是“加密替代 TLS”，而是“在 TLS 外观里，把特定客户端识别出来，同时尽量不显眼”。

### 我们在这个仓库里做到了什么

目前仓库里的代码已经能做到：

* 客户端生成符合当前实现约定的 REALITY `session_id`。
* 服务端在很早阶段读取 `ClientHello`，决定是继续 REALITY/TLS 路径，还是转发到 decoy 后端。
* decoy 转发可以按规则匹配，例如：
  * `serverNames`
  * `alpns`
  * `namedGroups`
* 配置可以通过 CLI 或 JSON/TOML 文件加载。

### 还没做到什么

这不是“完整复刻 Xray REALITY”。

当前实现更准确的定位是：

* 一个已经可运行的 Rustls 集成原型。
* 一个能说明协议接缝和工程边界的参考实现。
* 一个适合继续工程化，而不是直接宣布生产就绪的版本。

## 我们一路讨论出来的几个关键问题

### 1. REALITY 到底是不是“不要证书”

协议概念和当前代码实现要分开说。

从协议直觉上，很多人会把 REALITY 理解成“好像不是传统证书站点”。但在当前这个 Rustls 集成里，服务端仍然需要标准 TLS 证书和私钥，因为当前服务端入口仍然是 Rustls 的正常 `ServerConfig` 和证书链构造流程。

也就是说：

* 在本仓库当前实现里，服务端要提供证书和私钥。
* 自签名证书可以用于测试，但客户端必须信任它，或者显式关闭校验。
* 如果目标是公网实用，自签名证书通常不合适，除非你完全控制客户端信任链。

相关示例入口：

* `simpleserver.rs` 仍然要求 `--cert` 和 `--key`
* `tlsserver-mio.rs` 也仍然要求 `--certs` 和 `--key`

### 2. 我们为什么没有直接声称“已经和 Xray 一样”

因为两件事不同：

* “协议思想相近”
* “线上行为完全等价”

当前代码已经实现了 REALITY 风格的关键识别路径，但没有宣称做到以下所有事情：

* 与 Xray 的所有探测识别策略逐字节等价。
* 与 Xray 的所有配置语义完全一致。
* 对公网探测、长时间运行、复杂回退行为都经过了系统级验证。

所以它是“能工作、可解释、可扩展”的实现，不是“已经完全兼容 Xray 全部生产语义”的实现。

### 3. 我们到底实现的是协议，还是实现的是一个分流器

两者都有，但比重不同。

这套代码包含两层：

* 协议层：客户端生成 REALITY 风格 `session_id`，服务端验证 `ClientHello` 和相关字段。
* 分流层：服务端在握手前就决定，哪些连接继续走 REALITY/TLS，哪些连接改走 decoy backend。

后者在当前仓库里非常重要，因为“是否转去诱饵后端”正是实际部署时最关心的行为之一。

## 从字节进来到服务端回包：完整数据流

这是我们之前反复刨过的主线，也是最适合技术读者快速建立全局图景的部分。

### 第 1 步：客户端构造 `ClientHello`

客户端侧的关键扩展点在：

* `rustls/src/client/reality.rs`
* `rustls/src/client/config.rs`
* `rustls/src/client/hs.rs`
* `rustls-aws-lc-rs/src/reality.rs`

当前路径大致是：

1. Rustls 客户端在发送 `ClientHello` 前，开放了一个 `ClientHelloCallback` 钩子。
2. REALITY 路径把这个钩子包装成 `RealityClientHelloCallback`。
3. 它调用 `RealitySessionIdGenerator` 生成 32 字节 `session_id`。
4. 生成器可以是：
   * `PlaintextRealitySessionIdGenerator`
   * `SealingRealitySessionIdGenerator`
5. aws-lc-rs 侧提供了更贴近当前实现目标的安装辅助，例如：
   * `RealitySessionIdConfig`
   * `install_reality_session_id_generator_from_xray_fields()`

当前实现里，`session_id` 头部布局包含我们讨论过的这些信息：

* 3 字节 version
* 1 字节保留位，当前要求为 0
* 4 字节时间戳
* short_id 所在的 8 字节槽位

对于 sealing 版本，客户端还会结合：

* `ClientHello` 原始快照
* 当前密钥交换状态
* 服务端静态公钥

派生出用于封装 `session_id` 的密钥材料。

### 第 2 步：服务端预读 `ClientHello`

服务端示例主路径在：

* `examples/src/bin/tlsserver-mio.rs`

这里没有一上来就直接把流量完全交给 TLS 握手，而是先用：

* `rustls::server::Acceptor`

去预读 `ClientHello`。这样可以在完整握手前就做分流决策。

对应关键路径：

* `do_accept_read()`
* `try_finish_accept()`
* `fallback_target_for_client_hello()`

### 第 3 步：服务端决定“继续握手”还是“转发到 decoy”

服务端决策逻辑分成两层：

#### 第一层：规则选路

服务端先根据配置里的 `fallbackRules` 和默认 fallback target 决定“如果要回退，目标是谁”。

当前 matcher 支持：

* `serverNames`
* `alpns`
* `namedGroups`

对应关键逻辑在：

* `FallbackMatcher`
* `select_fallback_target()`

#### 第二层：REALITY 预筛

即使某个连接的 SNI 命中了允许值，也不代表它一定是我们期望的 REALITY 客户端。

所以当前实现还会检查预读到的原始 `ClientHello.session_id`：

* 是否长度为 32
* version 前缀是否匹配
* short_id 前缀是否匹配

对应关键函数：

* `client_hello_session_id()`
* `session_id_matches_reality()`

这一步的效果是：

* 看起来不像 REALITY 的连接，即使 SNI 合法，也能被导向 decoy。

### 第 4 步：如果是 REALITY/TLS 路径，就继续握手

如果连接没有被分流，代码会把之前缓冲的字节重新喂回正常 TLS 连接状态机：

* `start_tls_from_accept_buffer()`

然后继续标准 Rustls 握手和数据收发。

### 第 5 步：如果不是 REALITY 路径，就进入原始 TCP passthrough

如果连接被判定应该回退，它不会再继续当前 TLS 路径，而是：

* 建立到 decoy backend 的原始 TCP 连接
* 把预读缓冲的数据先写给 decoy
* 前后双向转发后续字节

关键函数包括：

* `start_fallback()`
* `try_front_read_passthrough()`
* `try_back_read_passthrough()`
* `flush_passthrough_writes()`

这就是“从数据进来，到服务端决定解密还是旁路，再把数据写回客户端”的核心链路。

## 服务端真正的 REALITY 校验在什么地方

如果前面的 example 层分流判定允许继续走 REALITY/TLS，真正的协议级校验会进一步进入 Rustls server 侧扩展点。

关键落点：

* `rustls/src/server/config.rs`
* `rustls/src/server/hs.rs`
* `rustls/src/server/reality.rs`
* `rustls-aws-lc-rs/src/reality.rs`

当前结构是：

1. Rustls server config 新增了 `ClientHelloVerifier`。
2. 服务端握手阶段在 `ExpectClientHello` 处理时，调用这个 verifier。
3. verifier 收到的是一个 `RealityClientHello` 视图。
4. aws-lc-rs 侧的 `RealityServerVerifierConfig` 会构建实际 verifier。
5. verifier 使用：
   * 客户端 `key_share`
   * 服务端静态私钥
   * `raw_client_hello`
   * `session_id`
   * 时间戳和 short_id 规则
   来验证当前 hello 是否满足我们定义的 REALITY 约束。

所以当前实现并不是只有 example 层的“猜测式路由”，它已经把 Rustls 核心握手路径也接上了一个 REALITY 风格的 `ClientHelloVerifier`。

## Xray 字段在当前 Rust 示例里分别对应什么

这是我们之前来回核对过很多次的点，因为名称相似但落点不完全一样。

在当前仓库里，可以这样理解：

* `shortId`
  * 客户端：`--reality-short-id`
  * 服务端：`--reality-short-id`
  * 配置：`reality.shortId`
* `publicKey`
  * 客户端：`--reality-public-key`
  * 配置：`reality.publicKey`
  * 含义：客户端持有服务端静态公钥，用来生成 REALITY `session_id`
* `privateKey`
  * 服务端：`--reality-private-key`
  * 配置：`reality.privateKey`
  * 含义：服务端持有对应静态私钥，用来验证 REALITY hello
* `serverName`
  * 客户端：`--server-name`
  * 服务端：`--reality-server-name`
  * 配置：`reality.serverName` 或 `reality.serverNames`
  * 含义：既是 TLS SNI 相关字段，也是当前 allowlist 决策的一部分
* `version`
  * 客户端和服务端都要求显式给出
  * 当前实现固定解释为 3 字节、6 个十六进制字符

如果你只想看当前仓库的映射表，可以直接看：

* `examples/README.md`

## 为什么我们最后把 fallback 规则做成可配置 matcher

这是工程上非常关键的一步。

一开始最容易想到的是：

* 不合法的流量统统转去一个固定 decoy 端口。

但实际使用很快会碰到问题：

* 不同探测流量可能想转不同 decoy
* 只看 SNI 太粗
* 仅凭“allowlist 命中”并不能说明它真是 REALITY 客户端

于是当前实现逐步演化出：

* 默认 `fallbackAddress + fallbackPort`
* 有序 `fallbackRules`
* 规则 matcher 支持：
  * `serverNames`
  * `alpns`
  * `namedGroups`
* 规则校验：
  * 至少要有一个 matcher
  * 端口不能为 0

这部分的意义不是“协议本身必须如此”，而是“真实部署里，光有协议校验不够，入口分流策略必须可控”。

## 当前实现和“真正可商用部署”的差距在哪里

这是我们后面收口时最明确的一条结论。

当前状态可以定义为：

* 可运行原型
* 可联调
* 可解释
* 可继续工程化

但还不应该直接当成“已经生产就绪”。

主要差距包括：

* 代码主体仍然在 examples 层
* 验证以 focused tests 和有限 live checks 为主
* 还没有系统性的并发、长期运行、异常流量、互操作覆盖
* 还没有完备的观测、统计、回滚、热更新和运维控制
* 并未宣称达到 Xray 全量语义兼容

所以更准确的描述是：

* 它已经不是纸上谈兵
* 但也还不是“直接上公网核心流量”的状态

## 适合怎么使用当前这套代码

如果按风险从低到高排序：

### 适合

* 本地验证
* 内网联调
* 受控灰度环境
* 继续做正式服务端工程化的基础代码

### 不适合直接默认认为没问题

* 无观测、无回滚方案的公网生产入口
* 需要声称“完全等价于 Xray REALITY”的场景
* 需要跨大量客户端生态做强兼容承诺的场景

## 给技术专家的实现索引

如果你想直接顺着代码看，这几条路径最关键：

### 客户端

* `rustls/src/client/config.rs`
  * `ClientHelloCallback`
  * `DangerousClientConfig::set_reality_session_id_generator()`
* `rustls/src/client/hs.rs`
  * 在发出 `ClientHello` 前调用 callback
* `rustls/src/client/reality.rs`
  * `RealitySessionIdGenerator`
  * `PlaintextRealitySessionIdGenerator`
  * `SealingRealitySessionIdGenerator`
* `rustls-aws-lc-rs/src/reality.rs`
  * `RealitySessionIdConfig`
  * `build_reality_client_config_from_xray_fields()`
  * `install_reality_session_id_generator_from_xray_fields()`

### 服务端核心握手扩展

* `rustls/src/server/config.rs`
  * `ClientHelloVerifier`
  * `DangerousServerConfig::set_reality_client_hello_verifier()`
* `rustls/src/server/hs.rs`
  * 在服务端处理 `ClientHello` 时调用 verifier
* `rustls/src/server/reality.rs`
  * `RealityClientHello`
* `rustls-aws-lc-rs/src/reality.rs`
  * `RealityServerVerifierConfig`

### 示例层分流入口

* `examples/src/bin/tlsclient-mio.rs`
  * 客户端 config 加载和 REALITY 参数接入
* `examples/src/bin/simpleserver.rs`
  * 最小服务端示例
* `examples/src/bin/tlsserver-mio.rs`
  * `resolve_reality_config()`
  * `fallback_target_for_client_hello()`
  * `select_fallback_target()`
  * `session_id_matches_reality()`

## 最后一句话

如果只问“这套代码现在到底是什么”，最准确的说法是：

它已经是一套把 REALITY 关键接缝真正接进 Rustls 的、可运行的、边界明确的参考实现；它足够让人看懂协议怎样落地，也足够作为下一步工程化的基础，但它还不应该被假装成已经完成全部生产语义和全部上线验证的最终形态。