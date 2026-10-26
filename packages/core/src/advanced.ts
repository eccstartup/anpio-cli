// @anpio-cli/core/advanced —— 底层字节 / 编码 / 签名构造原语。
//
// 签名器、验证器、自定义证明器 / 适配器才需要它们。为兑现"主入口小面"，
// 它们不进 `@anpio-cli/core` 主入口，但仍然公开、仍然稳定，只是换了入口。
// 主入口契约见 src/index.ts。

// 字节与编码
export { utf8, utf8From, sha256, bytesToBase64, base64ToBytes } from './crypto/encoding'
// base58btc（multibase 底层）
export { base58btcDecode, base58btcEncode } from './crypto/base58'
// multibase 公钥前缀
export { encodeMultibaseEd25519, encodeMultibaseSecp256k1 } from './crypto/multicodec'
// Ed25519 私钥 → 公钥（持有私钥的调用方自己推导公钥；SDK 自己的身份是在建号那一步一并导出的）
export { ed25519PublicKey } from './crypto/ed25519'
// secp256k1 公钥的 JWK 表示（ANP 附录 A A.3 / A.4：`k1_` 的绑定密钥以 `publicKeyJwk` 发布）
export { secp256k1PublicKeyToJwk } from './crypto/multicodec'
export type { Secp256k1PublicKeyJwk } from './crypto/multicodec'
// DID 文档里绑定密钥的表示（写入侧是严格的和类型：Ed25519 走 `Multikey`，secp256k1 走 JWK）
export type { DidPublicKey } from './crypto/didDocument'
// DID 文档的骨架（验证方法 + `authentication` / `assertionMethod`）。SDK 自己的身份走
// `createWebIdentity` / `loadOrCreateDevIdentity`；自己持有私钥、要分步造文档的调用方
// （本服务的群文档）从这里起步，`proof` 由它自己用 `signDidDocumentProofSync` 补上。
export { buildBaseDidDocument } from './crypto/didDocument'
// RFC 9421 签名构造与解析
export {
  ANP_COMPONENTS,
  parseSignatureInput,
  buildSignatureBase,
  serializeSignatureParams,
  buildSignatureInputHeader,
  buildContentDigestValue,
  signatureBaseBytes,
} from './crypto/signatureBase'
export type {
  CoveredComponent,
  ParsedSignatureInput,
  BuildSignatureBaseInput,
} from './crypto/signatureBase'
// ANP-02 签名器
export { signAnpLoginRequest } from './crypto/signer'
export type { SignAnpLoginInput } from './crypto/signer'
// ANP-02 §4 —— 把同一份证明装进 JSON envelope（WebSocket 首包 / 消息总线 / RPC 包装层）
export { signAnpJsonAuthRequest } from './crypto/jsonAuth'
export type { SignAnpJsonAuthInput, JsonAuthEnvelope, JsonAuthFields } from './crypto/jsonAuth'
// EVM 地址 / 签名
export { ethPersonalSignHash, recoverEthPublicKey, ethAddressFromPublicKey } from './wallet/eip1193'
// 证明适配层
export { anpProofAdapter, cryptoWalletProver, ANP_PROOF_KIND } from './protocol/anp'
// DID 文档的签发与「指定密钥」验签（ANP-03 §2.5.5 的自证 / 更新证明）
export { signDidDocumentProof, signDidDocumentProofSync, verifyDidDocumentProofWithKey } from './crypto/dataIntegrity'
export type { MessageSigner } from './crypto/dataIntegrity'
// dev shim 的身份缓存
export { loadOrCreateDevIdentity } from './connectors/anpDevShim'
