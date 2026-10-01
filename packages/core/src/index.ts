// connectx 公开 API —— 这是唯一权威的对外清单。
//
// 每个名字都显式列出（不再用 `export *`），所以：
//   1. "对外暴露什么"一眼可见，且能在 CI 里做快照防漂移（见 index.test.ts）；
//   2. 新增导出不会因为子模块一个 `export` 就自动变成公开契约；
//   3. 破坏性变更（增删改名）必须改这里，改动本身就被 semver 规则盯住。
//
// 收窄原则：主入口只留"用户会直接 import 的面"——配置 / 操作 / 连接器 / 钱包 /
// 密钥解析 / 身份格式 / 服务端验签 / 状态 / 错误，以及它们签名里用到的类型。
// 底层字节/编码/签名构造原语（utf8、base58、multibase 编码、RFC 9421 签名底、
// EVM 签名恢复、证明适配器等）降级到 `@agentx/core/advanced`（见 src/advanced.ts），
// 仍可 import，但不属于主契约。

// ---- 配置与操作 -------------------------------------------------------------
export { createConfig, selectWallet } from './config'
export { signRequest, login, register, update } from './actions'
export type { RegisterOptions, RegisterOutcome, UpdateOptions, UpdateOutcome } from './actions'
// 第二条注册契约：DID server **自己**的 JSON-RPC 接口（awiki-open-server 的 canonical
// User Service v1）。ANP-03 §2.5.3 L427 把程序化注册/管理留给实现方，所以这不是
// `register` 的一个变体，而是另一条线上契约：没有 RFC 9421 签名、没有 401 挑战、
// 服务端验的是所提交 `did_document` 自带的 DataIntegrityProof（§2.5.5）。
// ⚠️ 只支持 Ed25519（e1_）身份。
export { registerViaJsonRpc } from './actions'
export type { JsonRpcRegisterOptions } from './actions'
// ANP-02 §3.2.4.1 的错误词汇表：客户端一直用它解析服务端的挑战，服务端也得有同一套
// 名字去*发出*它——否则只能像 agent-on 那样把九种拒绝塌缩成三种。
export { isAnpAuthError, parseWwwAuthenticate } from './actions'
export type { AnpAuthError, WwwAuthenticateChallenge } from './actions'

// ---- 连接器 ------------------------------------------------------------------
export { anpDevShim } from './connectors/anpDevShim'
export type { AnpDevShimOptions } from './connectors/anpDevShim'
export { anpCli } from './connectors/anpCli'
export type { AnpCliOptions, AnpCliSource } from './connectors/anpCli'
export { chainWalletConnector } from './protocol/adapters/chain'
export type { ChainWalletConnectorOptions } from './protocol/adapters/chain'

// ---- 钱包 --------------------------------------------------------------------
export { chainWallet } from './wallet/eip1193'
export type { Eip1193Provider, ChainWalletOptions } from './wallet/eip1193'
export { keypairWallet } from './protocol/adapters/chain'
export type { KeypairWalletOptions } from './protocol/adapters/chain'
export type { IWallet } from './wallet/wallet'

// ---- 密钥解析（agent / CLI 输入边界）------------------------------------------
export { parsePrivateKey, parseMnemonic, parseKeystore, parsePem } from './keys/parse'
export type { ParsedKey, ParsedKeyCurve } from './keys/parse'

// ---- 身份格式（已冻结）--------------------------------------------------------
export { identityDid, domainServiceDid, webIdentityDid, normalizeChainId, normalizeAddress, subjectOf, stableSubjectId } from './identity'
export type { WbaDidKey, DidKeyCurve, SubjectId } from './identity'
// 指纹（RFC 7638 thumbprint）的读出侧：`identityDid` 把它绑进 DID，这里是它的逆——
// 给定曲线与公钥字节，得回 DID 里那一段（`e1_…` / `k1_…`）。ZKTODO1 §8.2 的入会去重
// 按「密钥指纹」建唯一索引，正是为了不绑指纹的 did:web 也能被同一个键覆盖。
export { didFingerprint } from './crypto/fingerprint'
export { buildWalletIdentity } from './protocol/anp'
export { createAnpIdentity } from './crypto/signer'
// 原生 `did:web`（附录 B）的产出侧：`createWebIdentity` 造一个 did:web 身份和它
// 要服务的文档（**没有** proof，也没有指纹可绑），再按 `didToUrl(did)` 发布出去。读取与
// 验证那一侧早就通了——`resolveDidDocument` 能解，且 WBA 专属检查本就对 did:web 让路。
export { createWebIdentity } from './crypto/webIdentity'

// ---- 服务端验签 ---------------------------------------------------------------
export { resolveVerificationKey, resolveDidDocument, verifyDidDocument, didToUrl, isSuperseded } from './crypto/resolveDid'
export { createDidDocumentStore } from './crypto/resolveDid'
// 带请求体的受控出站（P8 §2.4）：`fetchControlledJson` 把非 2xx 读成失败，而跨域那一层
// 要把它读成**答复**（ANP-02 §3.2.4.1 的 401 与挑战头就在状态和头上）。
export { fetchControlledResponse } from './crypto/resolveDid'
export type { FetchErrorCodes, ControlledRequest } from './crypto/resolveDid'
export type {
  ResolvedKey,
  ResolvedDidDocument,
  DidDocumentStore,
  ResolveDidOptions,
} from './crypto/resolveDid'
export { verifyHttpMessageSignature, verifyAnpJsonAuthRequest, createNonceStore } from './crypto/verify'
// ANP-02 §4 的验证半边：同一份证明装在 JSON envelope 里时从 `auth` 对象取字段，且
// `contentDigest` 绑定的是 `payload`——而不是像 §3 那样绑定整个消息体。
export type { VerifyHttpSignatureInput, VerifyJsonAuthInput, NonceStore, NonceStoreOptions } from './crypto/verify'
export { verifyAnpLoginRequest, anpErrorForResolveFailure, verifyHttpSignatureForServer } from './crypto/serverAuth'
export type {
  VerifyAnpLoginInput,
  AnpLoginIdentity,
  AnpLoginResult,
  AnpLoginFailure,
} from './crypto/serverAuth'
export { decodeMultibaseKey } from './crypto/multicodec'

// ---- Agent Description（ANP-07 `ad.json`）--------------------------------------
// 抓与发是同一形状的两半，一并列出：`fetchAgentDescription` 读 DID 文档的
// `AgentDescription` service 条目再抓 `serviceEndpoint`；`buildAgentDescription`
// 产出一份最小合规文档，`agentDescriptionService` 产出那条 service 条目。
// ANP 对 `ad.json` **没有路径约定**——service 条目就是唯一的定位方式，且它必须
// 在 DID 文档**签名之前**就在里面（proof 覆盖签名时刻的全部字段），所以 service
// 要经由 `createAnpIdentity` / `buildWalletIdentity` / `anpDevShim` 的 `service`
// 选项传入，不能事后追加。
export { fetchAgentDescription, buildAgentDescription, agentDescriptionService } from './crypto/agentDescription'
export { AGENT_DESCRIPTION_SERVICE_TYPE, HANDLE_SERVICE_TYPE } from './crypto/didDocument'
export type { DidDocumentService, DidDocumentServices } from './crypto/didDocument'
export type { AgentDescription, AgentDescriptionInput, ResolvedAgentDescription } from './crypto/agentDescription'

// ---- Agent Discovery（ANP-08 `.well-known/agent-descriptions`）------------------
// 与 ANP-07 是**两种文档**，所以是两个模块：`ad.json` 说的是「我是谁」，目录页说的是
// 「这个域名下有哪些」。读取按**普通 JSON** 取四个键（`@type` / `items[].@id` / `url` /
// `next`），不做 JSON-LD 展开（SDKTODO1 §B0）；产出照规范自己的示例发 JSON-LD
// `CollectionPage`。分页沿 `next` 递归到没有了为止（L94），但**必须有界**，且到达上限时
// **失败**而不是截断——截断后的清单和一个真的只有几个 agent 的域名分不开。
// 条目里的 `@id` 不在这里抓：发现只回答「发布了什么」，抓某一份是 `fetchAgentDescription`，
// 主机白名单在那边再判一次。
export { agentDescriptionIndexUrl, fetchAgentDescriptionIndex, buildAgentDescriptionIndex, AGENT_DESCRIPTIONS_PATH } from './crypto/agentDiscovery'
export type {
  AgentDescriptionIndexEntry,
  AgentDescriptionIndexPage,
  AgentDescriptionIndex,
  AgentDescriptionIndexInput,
  AgentDescriptionIndexOptions,
  ResolvedAgentDescriptionIndex,
} from './crypto/agentDiscovery'

// ---- WNS Handle（ANP-04）-------------------------------------------------------
// 「解析」与「校验」是两个强度：`resolveHandle` 只回答"这个 Provider 声称这个 Handle
// 指向哪个 DID"，那是一个**声称**；要拿来做事就需要 `verifyHandleBinding` 跑完 §6.3.1
// 的双向绑定（Provider 正向声明 + DID 持有者在 DID 文档里的 `ANPHandleService` 反向
// 声明)，并且分清 `exact-handle` 与 `provider-confirmed`——需要确认「具体 Handle」的
// 场景只能用前者。写方那一半是 `handleService` / `handleResolutionUrl` /
// `didConfirmationUrl`：产出那条 service 条目以及它的两种端点。
// ⚠️ 这里和 `RegisterOptions.handle` **不是一回事**：那个是 DID server 同意托管你时
// 绑定的名字（DID 内部的名字），这里是 `DID → 名字` 的外部映射。
export { parseHandle, handleResolutionUrl, didConfirmationUrl, handleService } from './crypto/wns'
export { resolveHandle, verifyHandleBinding } from './crypto/wns'
export type {
  ParsedHandle,
  HandleStatus,
  HandleResolutionDocument,
  ResolvedHandle,
  HandleFetchOptions,
  HandleBindingResult,
  HandleBindingFailure,
  HandleBindingVerification,
} from './crypto/wns'

// ---- DID 连续性 -----------------------------------------------------------------
// 更新链（§2.5–§2.6）+ 409 `did_superseded` 的响应式重试（§3.2）。查询能力做厚：
// `resolveDidChain` 是"我这个 DID 现在还是当前的吗"的唯一答案来源，登录/注册遇到
// 409 时走的就是它，调用方也可以自己先查一次。
export { resolveDidChain, createDidChainEdgeStore } from './did/chain'
export type {
  DidChain,
  DidChainHop,
  DidChainAssurance,
  DidChainOptions,
  DidChainEdge,
  DidChainEdgeStore,
} from './did/chain'
// 服务端自我描述（发现）：`GET <origin>/.well-known/did.json` 该服务为自己发布的文档。
// 注册要用的两件事只在那里：① 该 server 的 DID 域（**不等于** URL 里的 host——被
// `127.0.0.1:8765` 摸到的服务可能以 `did:wba:localhost` 发布），② 它自己的
// `ANPMessageService` 条目（server 会拿提交的文档跟自己的配置比，所以只能用它的那一份）。
export { discoverDidServer } from './did/discovery'
export type { DiscoveredDidServer, DiscoverDidServerOptions, DidServerService } from './did/discovery'

// ---- 状态 / 事件（可选上层）----------------------------------------------------
export { createStore } from './store'
export type { AnpStore, AnpStoreState } from './store'
export { createEventEmitter } from './events'
export type { EventEmitter, WalletEvent, WalletEventType } from './events'

// ---- ANP-09 消息 ---------------------------------------------------------------
// 信封 + P1 附录 A 的原发者证明 + 身份解析口子。CLI 与服务端共用这一份——两侧各写
// 一遍签名底，是这类实现最经典的 bug（[vendored-core.md](../../docs/design/vendored-core.md) §6）。
export {
  JSONRPC_VERSION,
  ANP_PROFILE,
  ANP_SECURITY_PROFILE,
  ANP_TARGET_KIND,
  ANP_META_FIELDS,
  ORIGIN_PROOF_SCHEME,
  JSON_RPC_ERROR,
  ANP_ERRORS,
  toErrorObject,
  anpRejection,
  rpcRejection,
  profileRejection,
  firstUnknownMetaField,
  parseEnvelope,
  isNotification,
  buildMessageRequest,
  buildMessageNotification,
} from './message/envelope'
export type {
  AnpProfileId,
  AnpSecurityProfile,
  AnpTargetKind,
  AnpTarget,
  AnpMeta,
  AnpOriginProof,
  AnpAuth,
  AnpParams,
  AnpRequest,
  AnpNotification,
  AnpErrorData,
  AnpErrorObject,
  AnpSuccessResponse,
  AnpErrorResponse,
  AnpResponse,
  AnpErrorCode,
  AnpErrorName,
  AnpRejection,
  EnvelopeCheck,
  BuildMessageRequestInput,
  BuildMessageNotificationInput,
} from './message/envelope'
export { signOriginProof, buildOriginProofAuth, ed25519OriginProofSigner, walletOriginProofSigner } from './message/sign'
export type { OriginProofSigner, SignOriginProofInput } from './message/sign'
// JSON-RPC 的**出站**半边：POST 到 `serviceEndpoint` + 响应形状判定。与 `envelope.ts`
// 分工是"信封长什么样"与"信封怎么走"，所以服务端可以只 import 前者。
// `postNotification` 是同一个 POST 的无响应形态（对端不必回 JSON，见 §5.6 L199）。
export { postMessage, postNotification, anpCodeOf } from './message/rpc'
export { verifyOriginProof, verifyOriginProofDetailed, originProofFreshness } from './message/verify'
export type {
  VerifyOriginProofInput,
  OriginProofFailure,
  OriginProofOutcome,
} from './message/verify'
export { DidServiceLocator, DidKeyResolver, isDidIdentity } from './message/locator'
export type {
  TrustAnchor,
  ServiceEntry,
  LocateOptions,
  ResolvedIdentityKey,
  ServiceLocator,
  KeyResolver,
} from './message/locator'
export {
  ANP_MESSAGE_SERVICE_TYPE,
  discoverMessageService,
  parseCapabilities,
  negotiateProfiles,
} from './message/discovery'
export type {
  AnpMessageServiceTarget,
  AnpCapabilities,
  DiscoverMessageServiceOptions,
} from './message/discovery'
export { idempotencyKey, idempotencyVerdict, idempotencyScopeFromMeta } from './message/idempotency'
export type { IdempotencyScope, IdempotencyRecord, IdempotencyVerdict } from './message/idempotency'
export { DEVICE_MANIFEST_TYPE, DidDeviceResolver } from './message/devices'
export type { DeviceEntry, DeviceRelationship, DeviceResolver, ResolvedDeviceManifest } from './message/devices'
// P1 附录 B 的共享 Object Proof Profile：**给任意对象**盖的章（P5 的 `prekey_bundle.proof`
// 是它的第一个用例）。与 `verifyDidDocumentProof` 分开，因为公钥不在这份被证明的对象里，
// 而在 **issuer 的** DID 文档里——"这份 proof 该由谁签"只有调用方答得了。
export { verifyObjectProof, verifyObjectProofDetailed } from './message/objectProof'
export type { VerifyObjectProofInput, ObjectProofOutcome, ObjectProofFailure } from './message/objectProof'
// DID URL 之间的**唯一**正确比较方式：`#dev-a-e2ee` 与 `did:web:…:alice#dev-a-e2ee` 是同一颗
// 钥的两种写法，字符串相等判不出这件事。P5 §6.5 第 2/4 项要服务端比较的都是 keyid
// （proof 的 `verificationMethod` vs 清单的 `signing_key_id`、`static_key_agreement_id` vs
// `e2ee_key_id`），所以在 service 里再写一遍这条规则等于把同一个语义抄成两份。
export { canonicalDidUrl } from './crypto/dataIntegrity'
// P1 附录 A.3 的 Signed Request Object 与它的摘要。服务端的幂等指纹就用它——
// 它已经覆盖 method / meta / body 的全部内容，另算一份摘要等于有两种"等价"。
export { signedRequestObject, canonicalizeSignedRequestObject, contentDigestOf } from './message/sro'
export type { SignedRequestObject } from './message/sro'

// ---- 错误模型 -----------------------------------------------------------------
export { ConnectxError, ConnectorUnavailableError, isConnectxError, errorCode } from './errors'
export type { ConnectxErrorCode, ConnectxErrorOptions, BlockedReason } from './errors'

// ---- 类型（public 签名必需）----------------------------------------------------
export type {
  WalletType,
  AnpStatus,
  AnpIdentity,
  AnpSigningIdentity,
  SignRequest,
  SignResult,
  LoginOptions,
  LoginOutcome,
  AnpConnector,
  AnpConfig,
  DidUpdateOptions,
  DidSupersededInfo,
  DidSupersededResolver,
  // 可注入的信封层（R2.1 结论 4）：`login` / `register` / `update` 三个选项共同 extends
  // 它，所以调用方要写一个 envelope 就必须能*命名*这些类型——从公开面里漏掉它，
  // 这个缝就只有 SDK 内部用得上。只改信封（url / method / headers / body），
  // 不改证明机制。
  SignedRequest,
  EnvelopeRequest,
  RequestEnvelope,
  SignedRequestTransport,
} from './types'
export type { Curve } from './crypto/multicodec'
// 高级定制类型：出现在 `prover?` / `proof?` / `buildWalletIdentity` 的 `descriptor?`
// 选项里，属于契约的一部分（自定义证明器 / 适配器时要用到）。
export type { ProofAdapter, WalletProver, IdentityDescriptor, Proof, BuildProofInput } from './protocol/proof'
