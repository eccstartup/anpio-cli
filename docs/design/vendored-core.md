# packages/core —— 从 anp-sdk 裁剪的协议原语

来源：`/Users/eccstartup/code/claude/anp-sdk`（`@connectx-sdk/core`，0.4.1）。
裁剪原则：**只留 ANP 协议原语**。产品化的东西（前端绑定、脚手架、ZK 隐私套件）全部不留。

行数按裁剪时点的 `src/core/` 实测。

---

## 1. 删除

| 删除项 | 来源行数 | 理由 |
|---|---|---|
| `core/zk/*`（15 个文件） | 4583 | 用户明确不要 ZK。已核实：**没有任何非 zk 模块 import 它**，删除是外科手术 |
| `src/zk.ts` | — | zk 的对外入口 |
| `packages/zk-pairing` | — | 独立的证明后端包 |
| `packages/react` / `packages/vue` / `src/react.ts` / `src/vue.ts` / `packages/brand` | — | 浏览器/UI 绑定，与 CLI + 服务端无关 |
| `core/connectors/anpExtension.ts` | 58 | 浏览器扩展连接器，CLI 与服务端都不走这条路 |
| `core/connectors/anpDevShim.ts` | 206 | 开发期 mock 连接器 |
| CLI 侧 `project.ts` / `generate/` / `template/` / `templates/` | ~1500 | 脚手架，**不是 ANP 协议**。这是"只做 ANP 相关 CLI"要砍掉的主体 |
| CLI 侧 `identity/zkstore.ts` | 151 | ZK 入会记录存储 |
| CLI 侧 `runZkLogin` / `readPlan` / `readSiteDescriptor` / `sameOrigin` / `sameRoot` / `namedAttributes` / `requestedAttributes` / `agreesWithMembership` / `loadBackendFactory` | ~600 | `auth.ts` 里 `--- anp login --zk ---` 分隔线以下的整段 |
| CLI 侧 `--zk` / `--zk-attrs` / `--zk-predicate` / `--zk-mode` / `--zk-backend` | — | 连同 `help/commands.ts` 里的 `ZK` OptionGroup 一起删 |

**ZK 的耦合面已核实**（2026-10-01）：`grep -rln "from './zk\|from '../zk'" src/ --include=*.ts | grep -v test` 在 `core/zk/` 之外**无命中**；
`actions.ts` 只有两处注释提到 `zk/client.ts` 复用了它的 `readError`，无代码依赖。

## 2. 保留（原样搬）

按包内路径，行数为实测。

**身份与密钥**
- `core/identity.ts`（357）—— `identityDid` / `webIdentityDid` / `domainServiceDid` / `subjectOf` / **`normalizeChainId` / `normalizeAddress`**（CAIP-10 规范化就住在这里）
- `core/keys/parse.ts`（233）—— 私钥 / 助记词 / keystore / PEM 解析
- `core/crypto/fingerprint.ts`（81）—— RFC 7638 指纹，`did:wba` 的 `e1_` / `k1_` 段

**签名与验签**
- `core/crypto/signatureBase.ts`（159）—— RFC 9421 签名底
- `core/crypto/dataIntegrity.ts`（289）—— DataIntegrityProof
- `core/crypto/verify.ts`（648）—— `verifyHttpMessageSignature` / `verifyAnpJsonAuthRequest` / nonce store
- `core/crypto/serverAuth.ts`（371）—— 服务端验登录请求
- `core/crypto/jsonAuth.ts`（138）—— JSON envelope 的证明半边

**DID 解析与更新链**
- `core/crypto/resolveDid.ts`（1126）—— `resolveDidDocument` / `resolveVerificationKey` / `didToUrl` / `isSuperseded`
- `core/crypto/didDocument.ts`（111）
- `core/did/chain.ts`（501）—— ANP-03 更新链
- `core/did/discovery.ts`（192）

**身份构造**
- `core/crypto/signer.ts`（122）、`core/crypto/webIdentity.ts`（57）
- `core/protocol/anp.ts`（325）、`core/protocol/proof.ts`（120）
- `core/protocol/adapters/chain.ts`（102）—— `keypairWallet` / `chainWalletConnector`
- `core/wallet/wallet.ts`（41）、`core/wallet/eip1193.ts`（213）—— **CAIP-10 那条路的入口**

**编码原语**
- `core/crypto/base58.ts`、`multicodec.ts`、`encoding.ts`

**配置与错误**
- `core/errors.ts`（185）、`core/types.ts`（297）、`core/config.ts`（33）、`core/defineConfig.ts`（36）、`core/store.ts`（148）、`core/nodeBuiltin.ts`（23）

**连接器**
- `core/connectors/anpCli.ts`（84）—— CLI 自己那条本地密钥路；CAIP-10 模式下 `chainId` + `address` 直接构成身份

## 3. 保留但需复核（协议相关，但可能超出当下范围）

| 模块 | 行数 | 判断依据 |
|---|---|---|
| `crypto/wns.ts` | 700 | WNS handle 解析。`did register --handle` 依赖它 —— **先查 `did.ts` 是否真的调用，再决定** |
| `crypto/agentDescription.ts` | 384 | ANP-07 Agent Description（`ad.json`）。**服务端要发自己的 description**，且它是 `serviceEndpoint`，与 P2 发现相邻 —— 倾向保留 |
| `crypto/agentDiscovery.ts` | 353 | ANP-07 的索引发现 —— 同上 |
| `core/actions.ts` | 1017 | 主体保留，但**必须把 ZK 分支切掉**后再看剩余规模 |
| `core/events.ts` | 37 | 仅登录事件流用 —— 视 `login` 是否保留而定 |

复核方式：从 `packages/cli` 与 `packages/service` 各自 `tsc --noEmit` 反向收敛——
**先搬全部候选，编译报谁缺谁，再把没人 import 的删掉**。不要事前凭名字猜。

## 4. 新增

`packages/core` 需要一块现在**没有**的能力：**ANP 消息信封的签与验**。
现有 `signRequest` 签的是 ANP-02 的登录请求对象；消息走的是另一套。

建议新增 `core/message/`：

| 文件 | 职责 |
|---|---|
| `envelope.ts` | JSON-RPC 2.0 信封的类型与校验：`jsonrpc === "2.0"`、`id` 非空字符串、`params` 必须是对象、**禁 batch**；顶层固定 `{meta, auth, body}` |
| `sign.ts` | 客户端侧：构造 Signed Request Object `{method, meta, body}` → RFC 8785 JCS 规范化 → RFC 9421 签名，`scheme` 固定 `anp-rfc9421-origin-proof-v1`，组件集合固定 `("@method" "@target-uri" "content-digest")`，`@target-uri` = `anp://{kind}/{pct-encoded did}` |
| `verify.ts` | 服务端侧：同一套的逆运算 + `keyid` 归属校验（`keyid` 所属 DID 必须等于 `meta.sender_did`，且该 keyid 必须被 `authentication` 授权） |
| `discovery.ts` | 从 DID 文档取唯一 `ANPMessageService` 条目（`id` / `type` / `serviceEndpoint` / `serviceDid` / `profiles[]` / `securityProfiles[]`），校验"每个 DID 文档只能有一个可跨域 ANPMessageService" |
| `idempotency.ts` | 幂等键 `(sender_did, target.did, method, operation_id)` 的规范化与比较 |

`sign` / `verify` 是**同一份规范化逻辑的两个方向**，必须同文件相邻或共享一个 `canonical.ts`——
分开写两份 JCS 是这类实现最经典的 bug 来源。

## 5. 与旧仓库的关系

裁剪之后**不再有依赖**。后续若 `anp-sdk` 修了协议 bug，需要**人工挑选**回迁，
不设自动同步。这是用户选定的代价（另一条路是依赖 npm 包，被否）。

因此 `packages/core` 里凡是"照搬"的文件，**保留原注释与规范行号引用**——
回迁时靠它们比对，别重写成一套自己的说法。
