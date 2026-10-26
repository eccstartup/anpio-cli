// 群备注扩展面（TODO6 §4.2）。
//
// 与通讯录（`contacts.ts`）是同一件事的两半，所以文件开头那段话在这里逐句成立：ANP 里
// **不存在**"我给这个群起了什么名"这种东西，也不该存在——群自己的名字是
// `group_profile.display_name`，住在群的 Host 上，由 `group.update_profile` 改，**每个
// 成员看到的都是它**。这一族方法存的是相反的东西：只有签名者本人看得见的称呼。所以它们的
// 权威是 TODO6 §4.2，本文件是它在服务端的唯一实现，字段名与形状要和 Rust 那边的
// `group set-remark` 对上。
//
// ## 为什么另起一本，不并进 `contacts`
//
// 通讯录那一本的键的另一头是一个 **agent**（`msg send --to` 能发的那种）。群是 P4 的
// `group` 寻址，是另一种东西：并进通讯录会让 `contacts list` 把群当人列出来、让
// `contacts resolve <名字>` 返回一个群 DID，再让 `msg send --to <那个名字>` 走上一条通往
// 群的 `direct.send`——而群读不了那条消息（没有"群的信箱"这回事，`deliveries` 会落一行
// `owner_did` 是群 DID、永远不被取走的记录）。两本书、两个含义，各自有各自的 Profile。
//
// ## 键取 group_did，不取 subject
//
// 这里**与 `contacts` 不同**，而不同是有理由的：`contacts` 键 `subject` 是因为 agent 的
// DID 内嵌钥指纹、`did update` 会把它挪走（§3.2），而群 DID 是本服务自己命名空间里的
// `did:web:…:g:<id>`（`groupDidDocument.ts`），不含指纹、搬不动。给它套一层 `subjectOf`
// 只是让读者去核一个恒等变换——`subjectOf` 对 `did:web` 原样返回。
//
// ## 不校验这个群住不住在本服务
//
// 存的是**我的**名字，不是群的事实。群在 P8 跨域那一侧时（本服务它不是 Host），这正是一本
// 本地名册该有的行为——要"先问群在不在"就得先往它的 Host 发一次 `group.get_info`，而那是
// `group info` 的事，不是起名的事。`contacts.put` 同理不校验对方存在（它也校验不了）。

import type { AnpMeta, AnpRejection } from '@anpio-cli/core'
import { anpRejection } from '@anpio-cli/core'
import type { Storage, StoredGroupRemark } from '../storage/types'
import { isNonEmptyString, unknownField } from './body'

/** §4.2 这条扩展面自己的 Profile。与 `x_anpiocli.contacts.v1` 分开：P1 §6.2.2 L277 说
 *  `meta.profile` 是"本次请求的唯一解释"，而"我给这个人起的名字"与"我给这个群起的名字"
 *  不是同一种解释。 */
export const GROUP_REMARKS_PROFILE = 'x_anpiocli.group_remarks.v1'

export const GROUP_REMARKS_LIST = 'group_remarks.list'
export const GROUP_REMARKS_PUT = 'group_remarks.put'
export const GROUP_REMARKS_REMOVE = 'group_remarks.remove'

const LIST_FIELDS = [] as const
const PUT_FIELDS = ['group_did', 'remark'] as const
const REMOVE_FIELDS = ['group_did'] as const

// ---- body 校验 ---------------------------------------------------------------

/** `group_remarks.list` 的正文是空的：读的是**整本**群名册。
 *
 *  与通讯录同一个理由——`group info` 要在一处回答"我给这个群起的什么名"，而把表留在
 *  客户端意味着一次调用就能拿到全部，不必按群去问。 */
export function validateGroupRemarksListBody(body: Record<string, unknown>): AnpRejection | undefined {
  return unknownField(body, LIST_FIELDS)
}

export function validateGroupRemarkPutBody(body: Record<string, unknown>): AnpRejection | undefined {
  const unknown = unknownField(body, PUT_FIELDS)
  if (unknown !== undefined) return unknown
  if (!isNonEmptyString(body.group_did)) {
    return anpRejection('anp.invalid_params_shape', 'body.group_did must be a non-empty string')
  }
  // `remark` 在这里是**必填**的，与 `contacts.put` 不同：那张表里缺席即"没有备注"是正常
  // 状态（写入路径 ② 每天在造没有名字的行），而这张表只有"我给这个群起了个名字"一条写入
  // 路径。缺了它，这次调用什么都没说；要清掉名字用 `group_remarks.remove`。
  if (!isNonEmptyString(body.remark)) {
    return anpRejection(
      'anp.invalid_params_shape',
      'body.remark must be a non-empty string; `group_remarks.remove` drops a name',
    )
  }
  return undefined
}

export function validateGroupRemarkRemoveBody(body: Record<string, unknown>): AnpRejection | undefined {
  const unknown = unknownField(body, REMOVE_FIELDS)
  if (unknown !== undefined) return unknown
  if (!isNonEmptyString(body.group_did)) {
    return anpRejection('anp.invalid_params_shape', 'body.group_did must be a non-empty string')
  }
  return undefined
}

// ---- 结果 --------------------------------------------------------------------

function groupRemarkJson(row: StoredGroupRemark): Record<string, unknown> {
  return {
    group_did: row.groupDid,
    remark: row.remark,
    created_at: row.createdAt,
    updated_at: row.updatedAt,
  }
}

function ownerOf(meta: AnpMeta): string {
  // `checkMethod` 已经保证 `meta.target.did === meta.sender_did`（self-addressed），所以
  // 这里只是把那个结论拿出来用；这本群名册永远是签名绑定的那个身份的。
  return meta.sender_did ?? ''
}

// ---- 处理 --------------------------------------------------------------------

export function readGroupRemarks(storage: Storage, meta: AnpMeta): Record<string, unknown> {
  return { group_remarks: storage.groupRemarks(ownerOf(meta)).map(groupRemarkJson) }
}

export function putGroupRemark(
  storage: Storage,
  meta: AnpMeta,
  body: Record<string, unknown>,
  acceptedAt: string,
): Record<string, unknown> {
  const groupDid = body.group_did as string
  const remark = body.remark as string
  const owner = ownerOf(meta)
  // 先查一下这一行在不在，只为回答 `created`——"起好了"与"改好了"是人看的一句话，而两件事
  // 在这里只差一次存在性判断。`created_at` 不靠它：那一列由存储层在冲突时保留。
  const existed = storage.groupRemarks(owner).some((row) => row.groupDid === groupDid)
  const stored = storage.upsertGroupRemark({
    ownerDid: owner,
    groupDid,
    remark,
    createdAt: acceptedAt,
    updatedAt: acceptedAt,
  })
  return { group_remark: groupRemarkJson(stored), created: !existed }
}

export function removeGroupRemark(
  storage: Storage,
  meta: AnpMeta,
  body: Record<string, unknown>,
): Record<string, unknown> {
  const groupDid = body.group_did as string
  return { group_did: groupDid, removed: storage.removeGroupRemark(ownerOf(meta), groupDid) }
}
