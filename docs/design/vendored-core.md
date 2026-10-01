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
| `core/connectors/anpExtension.ts` | 58 | 浏览器扩展连接器（`window.anp`），CLI 与服务端都不走这条路 |
| `core/connectors/index.ts` | 3 | 没人 import 的 barrel，随上面两个连接器一起删 |
| `core/defineConfig.ts` | 36 | `connectx.config.ts` 的类型 schema，只服务 `connectx project generate`——那一族已整族删除。**它是 `defineConfig` / `ConnectxConfig` 唯一的家，删它必须同步改 `index.ts` 与 `index.test.ts` 的公开面清单** |
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
- `core/errors.ts`（185）、`core/types.ts`（297）、`core/config.ts`（33）、`core/store.ts`（148）、`core/nodeBuiltin.ts`（23）

**连接器**
- `core/connectors/anpCli.ts`（84）—— CLI 自己那条本地密钥路；CAIP-10 模式下 `chainId` + `address` 直接构成身份
- `core/connectors/anpDevShim.ts`（206）—— **原打算删，收敛时改判保留**。理由是 §3 那条方法本身：
  `actions.{error,register,webpage}.test.ts` 与 `connectors/ids.test.ts` 四个测试文件拿它当连接器桩，
  删它就得先重写这四个覆盖 `register` / `update` 错误路径的测试。它是"没人 import 的才删"里的**有人 import**。
  注意它用 `localStorage`，是浏览器取向的；日后若要把这四个测试换成更小的桩，再删它不迟。

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
| `locator.ts` | **身份 → 服务条目 / 验证密钥** 的可插拔接口。见 §6 |

`sign` / `verify` 是**同一份规范化逻辑的两个方向**，必须同文件相邻或共享一个 `canonical.ts`——
分开写两份 JCS 是这类实现最经典的 bug 来源。

## 5. 与旧仓库的关系

裁剪之后**不再有依赖**。后续若 `anp-sdk` 修了协议 bug，需要**人工挑选**回迁，
不设自动同步。这是用户选定的代价（另一条路是依赖 npm 包，被否）。

因此 `packages/core` 里凡是"照搬"的文件，**保留原注释与规范行号引用**——
回迁时靠它们比对，别重写成一套自己的说法。

## 6. 留的口子：身份解析必须是可插拔的

**用户裁定（2026-10-01）**：CAIP-10 与消息的接合现在**不做**，
但**不能把以后兼容的路堵死**——"你要把这个口子留在这里"。

### 6.1 难点（原话记录）

> ANP 是查询 DID server 的，而区块链是查询链上数据的。

这句话点出的是**两套不同的信任根**，不只是两个不同的解析函数：

| | `did:wba` / `did:web` | CAIP-10 |
|---|---|---|
| 身份材料从哪来 | **取**（DID server 的 `did.json`） | **随请求内联带过来**（§4.3 禁止解析） |
| 信任根 | 标识符里的指纹，或域 + TLS | **地址由公钥派生**（`derive(pk) == account_address`） |
| 有没有"服务发现" | 有——文档里的 `service` 条目 | **没有**。账户 id 上没有任何地方可以问入口服务 |
| 更新 | ANP-03 更新链 | **无**。换钥即换账户 |

所以缺口不在"怎么验签"（提案已经把认证那半边写完了），
而在**第二条**：一个纯钱包身份的 agent，`sender_did` 有了，**ingress 没有**。

### 6.2 口子长什么样

core 里**不得**出现"身份就是 DID 文档"这个假设的硬编码。把两件事抽成接口：

```ts
/** 身份 → 它宣告的服务条目（可能为空）。 */
interface ServiceLocator {
  locate(identity: string, opts?: LocateOptions): Promise<ServiceEntry[]>
}

/** 身份 + keyid → 用来验签的密钥，以及**这份材料的信任来自哪里**。 */
interface KeyResolver {
  resolve(identity: string, keyid: string, opts?: ResolveOptions): Promise<ResolvedKey>
}
```

`ResolvedKey` 必须能表达**材料是怎么可信的**，因为两种绑定不可比：

```ts
type TrustAnchor =
  | { kind: 'fetched'; url: string }        // did:web：域 + TLS
  | { kind: 'fingerprint'; thumbprint: string } // did:wba：标识符承诺密钥
  | { kind: 'derived-address'; address: string } // CAIP-10：地址由公钥派生
```

第三条**必须**要求"先用它做派生校验、再验签"，顺序不能反（提案 §5.1）。

v1 只提供 `DidServiceLocator` 与 `DidKeyResolver` 两个实现。**接口先立着，
实现只有一个**——这不是过度设计，是用户明确要留的那道门。

### 6.3 硬约束：调用点不许判类型

**`packages/cli` 与 `packages/service` 里不得出现"这是 DID 还是账户 id"的分支。**
一旦有 `if (isDid(x))`，门就关上了。**所有身份都交给 locator / resolver**，
由它们决定怎么处理。

这条要写进代码评审清单。它是这个口子唯一会被堵死的方式——
接口立了但调用点绕过去直接 `resolveDidDocument`，等于没立。

### 6.4 现在做还是以后做

**抽象现在做，实现以后做。** 判断依据：

- 立接口 + 让调用点走接口：**便宜**。不增加行为，只是不改死。
- 实现链上 locator：**贵**，而且现在没有可依据的东西——规范里没有"链上注册表"这回事，
  它会是又一个自造概念（与 zk / CAIP-10 提案同一类，需要先回提上游）。
- 中间那条"让钱包身份能收发消息"的临时路（`x_` 回复地址扩展）**也不做**：
  P1 §12.1 规定未知核心 `meta` 字段 MUST 拒绝、只有 `x_` 前缀 MAY 忽略，
  所以它必须是一个**双方都认**的扩展，单方面加等于单方面不能用。

⇒ v1 的 `msg` / `group` 族只接受 DID（[cli.md](cli.md) §4）；
账户 id 在这两族上被拒，错误码 `caip10_has_no_ingress`，
**但拒绝发生在 locator 层，不是命令层的 `isDid()` 判断**——这就是口子。
