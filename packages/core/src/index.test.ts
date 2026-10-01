import { describe, it, expect } from 'vitest'
import * as api from './index'
import * as advanced from './advanced'

// 公开 API 契约快照：主入口 `@agentx/core` 的运行时导出（函数 / 类 / 常量）必须
// 恰好等于下面这份清单。`export type` 在运行时被擦除，不在此断言；类型面由
// src/index.ts 的显式 `export type` 列表锁定。
//
// 一旦有符号被误加 / 误删 / 改名，这里立刻红 —— 这正是"冻结公开契约"的机器
// 化护栏，避免 `export *` 时代那种"子模块加个 export 就静默变公开"的漂移。
const MAIN = [
  // 错误
  'ConnectxError',
  'ConnectorUnavailableError',
  'isConnectxError',
  'errorCode',
  // 配置与操作
  'createConfig',
  'selectWallet',
  'signRequest',
  'login',
  'register',
  // 第二条注册契约（0.3.x）：DID server 自己的 JSON-RPC 接口（ANP-03 §2.5.3 L427 把
  // 程序化注册留给实现方）。与 `register` 并列而非合并，因为两条线上契约没有共同点
  'registerViaJsonRpc',
  // 服务端自我描述：DID 域 + 它自己的 ANPMessageService 条目，都只能读不能猜
  'discoverDidServer',
  // 更新投递（0.3.x）：把一跳交给 DID server——退役文档由退役密钥签，后继文档随行
  'update',
  // 连接器
  'anpDevShim',
  'anpCli',
  'chainWalletConnector',
  // 钱包
  'chainWallet',
  'keypairWallet',
  // 密钥解析
  'parsePrivateKey',
  'parseMnemonic',
  'parseKeystore',
  'parsePem',
  // 身份格式
  'identityDid',
  // 裸域服务 DID（0.3.x）：无指纹、不可更新，只用于跨域服务到服务的 serviceDid。
  // 与 identityDid 分开，是为了让"不产出裸域用户身份"这条拒绝保持不变
  'domainServiceDid',
  // 原生 did:web（ANP-02 附录 B）：身份产出侧。与 identityDid 并列而非合并，
  // 因为这条方法没有指纹可绑，信任根是域的 TLS 证书加它服务的文档
  'webIdentityDid',
  'normalizeChainId',
  'normalizeAddress',
  // 稳定主体（0.3.0）：存储 / session 该以它为准，DID 只是会更新的线协议凭据
  'subjectOf',
  'stableSubjectId',
  // 密钥指纹（§8.2 的入会去重键）：`identityDid` 把指纹绑进 DID，这是它的逆
  'didFingerprint',
  'buildWalletIdentity',
  'createAnpIdentity',
  'createWebIdentity',
  // 服务端验签
  'resolveVerificationKey',
  'resolveDidDocument',
  'verifyDidDocument',
  'createDidDocumentStore',
  'didToUrl',
  'verifyHttpMessageSignature',
  // ANP-02 §4：同一份证明装在 JSON envelope 里，字段从 `auth` 取、摘要绑 `payload`
  'verifyAnpJsonAuthRequest',
  'createNonceStore',
  'verifyAnpLoginRequest',
  'decodeMultibaseKey',
  // ANP-02 §3.2.4.1 错误词汇表：服务端要发出这些值，就得先有同一套名字
  'isAnpAuthError',
  'parseWwwAuthenticate',
  // DID 连续性（0.3.0）：更新链 + 409 did_superseded 的响应式重试
  'resolveDidChain',
  'createDidChainEdgeStore',
  // resolveDidDocument 故意返回被顶替的文档（它们是证据，不是坏数据），
  // 所以调用方必须自己用这个谓词区分
  'isSuperseded',
  // Agent Description（ANP-07 ad.json）：抓与发是同一形状的两半
  'fetchAgentDescription',
  'buildAgentDescription',
  'agentDescriptionService',
  'AGENT_DESCRIPTION_SERVICE_TYPE',
  // Agent Discovery（ANP-08 .well-known/agent-descriptions）：与 ANP-07 是两种文档——
  // ad.json 回答「我是谁」，目录页回答「这个域名发布了哪些」，读 + 产两侧都在这。
  'agentDescriptionIndexUrl',
  'fetchAgentDescriptionIndex',
  'buildAgentDescriptionIndex',
  'AGENT_DESCRIPTIONS_PATH',
  // WNS Handle（ANP-04）：解析只是拿到 Provider 的**声称**，双向绑定校验才是结论。
  // 写方那一半产出 `ANPHandleService` 条目与它的两种端点（公开 / 私密确认）。
  'parseHandle',
  'handleResolutionUrl',
  'didConfirmationUrl',
  'handleService',
  'HANDLE_SERVICE_TYPE',
  'resolveHandle',
  'verifyHandleBinding',
  // ANP-09 消息：信封 + 错误码表（服务端发的码与客户端读的码出自同一份）
  'JSONRPC_VERSION',
  'ANP_PROFILE',
  'ANP_SECURITY_PROFILE',
  'ANP_TARGET_KIND',
  'ANP_META_FIELDS',
  'ORIGIN_PROOF_SCHEME',
  'JSON_RPC_ERROR',
  'ANP_ERRORS',
  'toErrorObject',
  'anpRejection',
  'rpcRejection',
  'firstUnknownMetaField',
  'parseEnvelope',
  'isNotification',
  'buildMessageRequest',
  // P1 附录 A 的原发者证明：签与验共用 `message/sro.ts` 的全部规范化
  'signOriginProof',
  'buildOriginProofAuth',
  'ed25519OriginProofSigner',
  'walletOriginProofSigner',
  'verifyOriginProof',
  'verifyOriginProofDetailed',
  'originProofFreshness',
  // P1 §5–§6 的出站半边：POST + 响应形状判定。与信封构造分开，服务端只 import 前者
  'postMessage',
  'anpCodeOf',
  // 身份解析的口子（vendored-core §6）：调用点只认 locator / resolver，不判身份类型
  'DidServiceLocator',
  'DidKeyResolver',
  'isDidIdentity',
  // P2 发现：静态 hint 与运行时能力分开持有，§8.3 的"以运行时为准"有名字
  'ANP_MESSAGE_SERVICE_TYPE',
  'discoverMessageService',
  'parseCapabilities',
  'negotiateProfiles',
  // P1 §9 幂等：算键与判定（存与事务在服务端）
  'idempotencyKey',
  'idempotencyVerdict',
  'idempotencyScopeFromMeta',
  // P1 附录 A.3 的 Signed Request Object：幂等指纹与签名底共用同一份规范化
  'signedRequestObject',
  'canonicalizeSignedRequestObject',
  'contentDigestOf',
  // 状态 / 事件
  'createStore',
  'createEventEmitter',
]

const ADVANCED = [
  // 字节与编码
  'utf8',
  'utf8From',
  'sha256',
  'bytesToBase64',
  'base64ToBytes',
  // base58btc
  'base58btcDecode',
  'base58btcEncode',
  // multibase 公钥前缀
  'encodeMultibaseEd25519',
  'encodeMultibaseSecp256k1',
  // secp256k1 公钥的 JWK 表示（ANP 附录 A A.3 / A.4：`k1_` 的绑定密钥以 `publicKeyJwk` 发布）
  'secp256k1PublicKeyToJwk',
  // RFC 9421 签名构造与解析
  'ANP_COMPONENTS',
  'parseSignatureInput',
  'buildSignatureBase',
  'serializeSignatureParams',
  'buildSignatureInputHeader',
  'buildContentDigestValue',
  'signatureBaseBytes',
  // ANP-02 签名器
  'signAnpLoginRequest',
  // ANP-02 §4 —— 把同一份证明装进 JSON envelope
  'signAnpJsonAuthRequest',
  // EVM 地址 / 签名
  'ethPersonalSignHash',
  'recoverEthPublicKey',
  'ethAddressFromPublicKey',
  // 证明适配层
  'anpProofAdapter',
  'cryptoWalletProver',
  'ANP_PROOF_KIND',
  // DID 文档的签发（ANP-03 §2.5.5）
  'signDidDocumentProof',
  'signDidDocumentProofSync',
  'verifyDidDocumentProofWithKey',
  // dev shim 身份缓存
  'loadOrCreateDevIdentity',
]

describe('public API surface', () => {
  it('@agentx/core main entry exports exactly the curated value surface', () => {
    expect(Object.keys(api).sort()).toEqual([...MAIN].sort())
  })

  it('@agentx/core/advanced entry exports exactly the low-level primitives', () => {
    expect(Object.keys(advanced).sort()).toEqual([...ADVANCED].sort())
  })

  it('main and advanced surfaces do not overlap', () => {
    const overlap = MAIN.filter((n) => ADVANCED.includes(n))
    expect(overlap).toEqual([])
  })
})
