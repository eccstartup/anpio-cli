// 通讯录扩展面（TODO6 §3）。
//
// 与取件面（`inbox.ts`）同一个道理：规范里**不存在**"备注"这种东西，也不该存在
// （TODO6 §3.2 把 remark / nickname / subject 三者分开，只有 subject 是协议给的），
// 所以这一族方法没有可援引的规范条款，它们的权威就是 TODO6 §3，本文件是它在服务端的
// 唯一实现，字段名与形状要和 Rust 那边的 `contacts` 命令族对上。
//
// 与取件面的第二处相同：`validateXxxBody` 是"这个请求能不能答"，`readXxx` / `putXxx` /
// `removeXxx` 是"答什么 / 改什么"。认证、信封、`target.did == sender_did` 的绑定都在上面
// 几层，这里拿到的已经是验过签的 params。
//
// ## 键取 subject，不取 did
//
// 这是 TODO6 §3.2 的支点，写在 handler 里而不是让调用方传：`did` 会随换钥挪走
// （`did update` 就是干这个的），备注挂 `did` 上就会在换钥那一刻静默消失。`subjectOf`
// 把指纹那一段去掉，剩下的路径正是"还是同一个人"。让客户端传 subject 会多一处定义，
// 两处一旦不一致，表现是"换钥后备注不见了"——一个没人会立刻联想到键选择的症状。
//
// 用的是 core 的 `subjectOf` 而不是 `stableSubjectId`：前者是全函数（did:web / CAIP-10
// 原样返回），后者只认 did:wba、别的抛。RPC 层不该因为一个格式奇怪的 DID 回 500，而
// Rust 客户端的 `identity::did::subject_of` 与前者逐字同形——两边算出的键因此一样，
// 客户端不必为了知道键而问服务端。

import type { AnpMeta, AnpRejection } from '@agentx/core'
import { anpRejection, subjectOf } from '@agentx/core'
import type { Storage, StoredContact } from '../storage/types'
import { isNonEmptyString, unknownField } from './body'

/** §3 这条扩展面自己的 Profile。`x_` 前缀是 P1 §12 给扩展留的命名空间，取值不是任何一个
 *  规范 Profile——混进去等于让一个只实现规范的服务看起来支持它（`capabilities.ts` 把
 *  `x_` 那批单独列在 `x_agentx` 块里）。 */
export const CONTACTS_PROFILE = 'x_agentx.contacts.v1'

export const CONTACTS_LIST = 'contacts.list'
export const CONTACTS_PUT = 'contacts.put'
export const CONTACTS_REMOVE = 'contacts.remove'

const LIST_FIELDS = [] as const
const PUT_FIELDS = ['did', 'remark'] as const
const REMOVE_FIELDS = ['subject'] as const

// ---- body 校验 ---------------------------------------------------------------

/** `contacts.list` 的正文是空的：读的是**整本**通讯录。
 *
 *  不做"按名字查一条"的服务端方法，是因为判定重名要能列出候选，而候选只有拿到全表才列得
 *  出来；把名单留在客户端，`resolve` 那套"两个 Alice 就拒并列出两个"的规则只有一处实现。 */
export function validateContactsListBody(body: Record<string, unknown>): AnpRejection | undefined {
  return unknownField(body, LIST_FIELDS)
}

export function validateContactPutBody(body: Record<string, unknown>): AnpRejection | undefined {
  const unknown = unknownField(body, PUT_FIELDS)
  if (unknown !== undefined) return unknown
  if (!isNonEmptyString(body.did)) {
    return anpRejection('anp.invalid_params_shape', 'body.did must be a non-empty string')
  }
  // `remark` 缺省即"没有备注"，是一个正常状态（把人加进通讯录而先不起名）。它在场时
  // 必须是个非空字符串：空串与缺省是同一件事的两种写法，而两种写法会让"这一行到底有没有
  // 备注"变成要看谁写的。
  if (body.remark !== undefined && !isNonEmptyString(body.remark)) {
    return anpRejection('anp.invalid_params_shape', 'body.remark must be a non-empty string when present')
  }
  return undefined
}

export function validateContactRemoveBody(body: Record<string, unknown>): AnpRejection | undefined {
  const unknown = unknownField(body, REMOVE_FIELDS)
  if (unknown !== undefined) return unknown
  if (!isNonEmptyString(body.subject)) {
    return anpRejection('anp.invalid_params_shape', 'body.subject must be a non-empty string')
  }
  return undefined
}

// ---- 结果 --------------------------------------------------------------------

/** 一行通讯录。`remark` 缺席报 `null` 而不是省略这个键：省略会让"没有备注"与"服务端这版
 *  还不返回备注"在客户端看来一样，而后者是一个该立刻暴露的不一致。 */
function contactJson(row: StoredContact): Record<string, unknown> {
  return {
    subject: row.subject,
    did: row.did,
    remark: row.remark ?? null,
    created_at: row.createdAt,
    updated_at: row.updatedAt,
  }
}

function ownerOf(meta: AnpMeta): string {
  // `checkMethod` 已经保证 `meta.target.did === meta.sender_did`（self-addressed），
  // 所以这里只是把那个结论拿出来用；这本通讯录永远是签名绑定的那个身份的。
  return meta.sender_did ?? ''
}

// ---- 处理 --------------------------------------------------------------------

export function readContacts(storage: Storage, meta: AnpMeta): Record<string, unknown> {
  return { contacts: storage.contacts(ownerOf(meta)).map(contactJson) }
}

export function putContact(
  storage: Storage,
  meta: AnpMeta,
  body: Record<string, unknown>,
  acceptedAt: string,
): Record<string, unknown> {
  const did = body.did as string
  const remark = isNonEmptyString(body.remark) ? body.remark : undefined
  const owner = ownerOf(meta)
  const subject = subjectOf(did)
  // 先查一下这一行在不在，只为回答 `created`——`contacts add` 那句"加好了"与"更新了"
  // 是人看的一句话，而两件事在这里只差一次存在性判断。`created_at` 不靠它：那一列在
  // 冲突时由存储层保留，答案从写回来的那一行取。
  const existed = storage.contacts(owner).some((row) => row.subject === subject)
  const stored = storage.upsertContact({
    ownerDid: owner,
    subject,
    did,
    ...(remark !== undefined ? { remark } : {}),
    createdAt: acceptedAt,
    updatedAt: acceptedAt,
  })
  return { contact: contactJson(stored), created: !existed }
}

export function removeContact(
  storage: Storage,
  meta: AnpMeta,
  body: Record<string, unknown>,
): Record<string, unknown> {
  const subject = body.subject as string
  return { subject, removed: storage.removeContact(ownerOf(meta), subject) }
}
