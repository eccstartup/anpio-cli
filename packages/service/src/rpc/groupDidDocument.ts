// B1b-A2 —— 群自己的 DID 文档。
//
// 群 DID 住在**本服务自己**的命名空间里（`group_did = serviceDid + ":g:" + <id>`，
// groups.md §2），所以按 TODO3 §0 的裁定，那份文档也由本服务发布——A3 只是把它挂到一个
// URL 上，形状与签名在这里定。
//
// 三件东西必须有，缺一条这份文档就白发了：
//
// 1. **一个验证方法，同时进 `authentication` 与 `assertionMethod`。** 前者让它能作为
//    群的身份被认证，后者是 `group_receipt.proof` 的归处（groups.md §7.9 L516：
//    `proof.verificationMethod` MUST 指向文档里被 `assertionMethod` 授权的那一支）。
//    `buildBaseDidDocument` 两处都写 `keyid`，所以这一条是构造出来的，不是配出来的。
// 2. **一条声明了 `serviceDid` 的 `ANPMessageService` 条目。** 这条文档的全部意义就是让
//    别的域据此找到我们（P8 §5.2 L215–221），而 §6.2.1 L327 要求参与跨域的服务条目
//    **MUST** 声明 `serviceDid`。条目取自 `well-known.ts` 的同一份清单，只有 `id` 换成
//    群的（服务条目住在被描述的那个 DID 的文档里）。
// 3. **一份自签的文档证明。** 见下面 `buildGroupDidDocument` 的注释。

import { parsePrivateKey } from '@agentx/core'
import {
  buildBaseDidDocument,
  ed25519PublicKey,
  encodeMultibaseEd25519,
  signDidDocumentProofSync,
} from '@agentx/core/advanced'
import type { Config } from '../config'
import type { Storage } from '../storage/types'
import { buildServiceEntry, type ServiceEntry } from '../well-known'

/** The verification method's fragment. `didDocument.ts` / `signDidDocumentProof` 只看
 *  `keyid`，对 fragment 的拼法没有规定；取 `key-1` 是因为它是 `did:web` 文档里最常见的
 *  那一个，别的域的手写解析器大概率已经见过它。 */
export const GROUP_KEY_FRAGMENT = 'key-1'

/** 群的验证方法要不要进 `authentication` / `assertionMethod`，由这个 id 决定；A5 签回执时
 *  填进 `proof.verificationMethod` 的也是它。**一处定义**，因为它同时是文档里的声明和证明
 *  里的引用，两处各写一遍就会出现"签的是 key-1、文档里挂的是 key-2"那种验不过又不报错的
 *  状态。 */
export function groupDidKeyId(groupDid: string): string {
  return `${groupDid}#${GROUP_KEY_FRAGMENT}`
}

/** 群文档里的服务条目：`well-known.ts` 那条原样搬过来，只换 `id`。
 *
 *  `well-known.ts` 的注释说嵌入方要把 DID 换成文档所有者的 DID——群文档正是那种嵌入方，
 *  所以这个替换落在这里，而不是让 A3 的路由顺手改一改返回的 JSON。 */
export function groupServiceEntry(config: Config, groupDid: string): ServiceEntry {
  return { ...buildServiceEntry(config), id: `${groupDid}#anp-message-service` }
}

export interface GroupDidDocumentInput {
  groupDid: string
  /** hex 的 32 字节种子，就是 `group_keys.private_key` 那一列。
   *  `parsePrivateKey` 与 `AGENTX_KEY_FILE` 认的是同一个形状（groups.md §2.1）。 */
  privateKeyHex: string
  serviceEntry: ServiceEntry
}

/** 造并签一份群文档。
 *
 *  **签名不是为了解析通过。** `documentProofPolicy` 对原生 `did:web` 直接返回 `skipped`，
 *  对末段不是 `e1_` 的 `did:wba` 在默认 `lenient` 下是"有则验、无则收"（resolveDid.ts 的
 *  `documentProof` 注释）——所以去掉这三行，文档照样能被解析。它在这里是为了别的事：
 *  `assertionMethod` 要有一个公开的归处（A5 的回执签名读它）、自签是"这把钥确实属于这个
 *  群"的唯一声明、以及 `strict` 档的部署下这份文档依然成立。**别把它读成"没有它就解析不
 *  了"**——那样下一个人会以为可以拿它换解析失败时的容错。
 */
export function buildGroupDidDocument(input: GroupDidDocumentInput): Record<string, unknown> {
  const { privateKey } = parsePrivateKey(input.privateKeyHex, 'ed25519')
  const keyid = groupDidKeyId(input.groupDid)
  const document = buildBaseDidDocument({
    did: input.groupDid,
    keyid,
    publicKeyMultibase: encodeMultibaseEd25519(ed25519PublicKey(privateKey)),
    // 服务条目必须在**签名之前**进来：`proof` 覆盖签的时候文档里已有的每个字段，事后追加的
    // `service` 不在覆盖范围内，那份文档会验不过（didDocument.ts 的 `BaseDidDocumentInput`
    // 注释，ANP-03 §2.5.5）。
    service: [input.serviceEntry],
  })
  document.proof = signDidDocumentProofSync(document, keyid, privateKey)
  return document
}

/** 按群 id 取文档——A3 的路由就是这一句。`undefined` 有两种来路，路由那边都答 404：
 *
 *  - 群不存在：陌生人猜了个 id，这是"这里没有你问的东西"。
 *  - 群存在但没有钥：v11 之前建的群（A1 的决定是**不补铸**——事后铸出来的那把不是此前
 *    任何一句关于这个群的话所依据的那把，`groupSigningKey` 的注释）。
 *
 *  两者都不是"我们坏了"，所以都不该是 500。 */
export function groupDidDocument(
  storage: Storage,
  config: Config,
  groupDid: string,
): Record<string, unknown> | undefined {
  if (storage.group(groupDid) === undefined) return undefined
  const key = storage.groupSigningKey(groupDid)
  if (key === undefined) return undefined
  return buildGroupDidDocument({
    groupDid,
    privateKeyHex: key.privateKeyHex,
    serviceEntry: groupServiceEntry(config, groupDid),
  })
}
