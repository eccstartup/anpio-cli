// C13 —— P6 §12 的两条通知路径：把一次被接受的控制动作装配成**设备定址**的信封，写进
// Device Delivery Queue。
//
// ## 为什么在处理器里写、而不是像 P4 那样交给 outbox
//
// P4 的 `group.state_changed` 是按 **DID** 定址的，`deliver()` 顺手也写一行 `deliveries`
// （C7 的拉取面要给本地设备），出站推送交给 `delivery/worker.ts`。P6 两条路都不是：
//
//   - §12.6 L1502 按 `(recipient_did, recipient_device_id)` 键控，且 L1523 逐字说这条队列
//     "是投递机制，不是群历史"，本 Profile **不定义**任何 P6 历史拉取方法；
//   - [e2ee-group.md] §6 那一节论证过：P6 信封一旦进 `deliveries`，就等于用一条违反
//     §12.6 末段的路径（自述设备字段当权威）把它们暴露出去。
//
// 所以是**另一张表**、**另一个 worker**（`delivery/deviceQueue.ts`），而装配在这里——与受理
// 同一个事务。理由与 P4 那份一样：队列行必须与"这次动作被接受了"是同一件事的两个写法，
// 分两个事务就会出现"账记了、信封没排队"或反过来。
//
// ## 两份信封，两种安全模式
//
//   - `group.incoming`（应用密文，§12.5）：`group-e2ee`，**保留**原 `params.auth`（§13.6）。
//   - `group.e2ee.notice`（Commit / Welcome，§12.2）：`transport-protected`，**不带** proof
//     （§13.6 L1663 逐字：notice 不带 `origin_proof`，附一个"看起来像签名"的反而违规）。
//
// ## 谁收哪一封
//
//   create  不发——初始成员是自己，没有 Commit 要投，也没有 Welcome。
//   add     commit 给**加完之后**的每一条 active leaf（含新 leaf，§12.3）+ welcome 给新 leaf。
//   remove  commit 给每条**保留的** leaf + final notice 给被移除的那一条（§12.3）。
//   send    incoming 给每一条 active leaf（§12.5），**逐叶一份**，只有 target 与
//           recipient_device_id 变。
//
// 队内次序靠入队次序（`StoredDeviceEnvelope.seq` 在 `(did, device)` 内自增），所以 §6.1
// 那条"最终通知排在已入队的应用信封之后"就是"**先**写应用信封、**后**写最终通知"，而
// §12.6 那句"Remove 被接受之后 MUST NOT 再为该 leaf 入队新的应用信封"由 `activeGroupLeaves`
// 天然保证：它只回 `state = 'active'` 的行，被移除的那条已经 `terminal` 了。

import { randomBytes } from 'node:crypto'
import type { AnpMeta } from '@agentx/core'
import type { Storage, StoredGroupLeaf } from '../storage/types'
import { GROUP_E2EE_PROFILE, isPlainObject, nonEmptyString } from './groupE2ee'

/** `group.e2ee.notice` 与 P6 `group.incoming` 两个方法名。放在这里而不是 `groups.ts`：
 *  `groups.ts` 那个 `GROUP_INCOMING` 是 P4 Base 的同名通知，两者共用方法名、形状不同。 */
export const GROUP_E2EE_NOTICE = 'group.e2ee.notice'
export const GROUP_INCOMING_P6 = 'group.incoming'

/** §12.2.2 L1426：notice 那一档的安全模式写死 `transport-protected`，与群的策略无关。
 *  §12.5 L1484：`group.incoming` 那一档是 `group-e2ee`。 */
const NOTICE_SECURITY_PROFILE = 'transport-protected'
const INCOMING_SECURITY_PROFILE = 'group-e2ee'

/** `StoredDeviceEnvelope.kind` 的四个取值（§6.1 那张表）。 */
export const ENVELOPE_INCOMING = 'incoming'
export const ENVELOPE_COMMIT = 'commit'
export const ENVELOPE_WELCOME = 'welcome'
export const ENVELOPE_FINAL_NOTICE = 'final-notice'

/** 一次发射需要的东西，结构化地取——为的是这个文件不 import `GroupControlContext`，
 *  依赖保持单向（`groupControl.ts` → 这里）。 */
export interface EnvelopeContext {
  storage: Storage
  /** RFC 3339，一次请求一个时刻。信封自己的 `meta.created_at` 与队列行的两个时刻都用它。 */
  acceptedAt: string
  /** 被接受的提交的 `meta`，按 §12.5 保留进信封。 */
  meta: AnpMeta
  /** 被接受的提交的 `params.auth`。只有 `group.incoming` 用它（§13.6）。 */
  auth?: unknown
}

/** §13.6 L1683：`extra_meta` 的保留字黑名单，逐字。 */
const RESERVED_META = new Set([
  'profile',
  'security_profile',
  'sender_did',
  'sender_device_id',
  'target',
  'recipient_device_id',
  'message_id',
  'operation_id',
  'content_type',
  'created_at',
])

/**
 * §13.6 L1678–1685 的重建输入。
 *
 * 它记的是**提交时**的 `meta.created_at`（信封自己那个 `created_at` 是投递时刻，被覆写
 * 掉了），以及本 Profile 不要求信封保留的其它 meta 字段。这两样是接收方**重建不出**的
 * 那部分——`@method` 与 `@target-uri` 都能从信封推导，不在其中。
 *
 * `origin_context` **MUST** 在场（L1678），所以哪怕两样都没有，也写出一个空对象。
 */
function originContext(meta: AnpMeta): Record<string, unknown> {
  const extra: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(meta)) {
    if (RESERVED_META.has(key)) continue
    extra[key] = value
  }
  return {
    ...(nonEmptyString(meta.created_at) ? { created_at: meta.created_at } : {}),
    ...(Object.keys(extra).length > 0 ? { extra_meta: extra } : {}),
  }
}

/**
 * §12.5 L1489：`params.auth` **原样**保留 `scheme` 与 `origin_proof`，并加一个
 * `origin_context`。三个键显式写出而不是展开——展开会把提交里任何别的键一起带进去，而
 * "原样"说的是那两个字段，不是整个对象。
 */
function preservedAuth(ctx: EnvelopeContext): Record<string, unknown> | undefined {
  const auth = ctx.auth
  if (!isPlainObject(auth)) return undefined
  return {
    scheme: auth.scheme,
    origin_proof: auth.origin_proof,
    origin_context: originContext(ctx.meta),
  }
}

function newId(): string {
  return randomBytes(16).toString('base64url')
}

/** 两条 notice 路径共用一个信封骨架（§12.2.2）。只有 `body` 与 target 不同。 */
function noticeMeta(recipientDid: string, recipientDeviceId: string, groupDid: string, messageId: string, operationId: string, acceptedAt: string): AnpMeta {
  return {
    profile: GROUP_E2EE_PROFILE,
    security_profile: NOTICE_SECURITY_PROFILE,
    // §12.2.2 L1428：`sender_did` SHOULD 等于 `group_did`——发起者是群自己。
    sender_did: groupDid,
    target: { kind: 'agent', did: recipientDid },
    recipient_device_id: recipientDeviceId,
    message_id: messageId,
    operation_id: operationId,
    created_at: acceptedAt,
  }
}

function enqueue(
  ctx: EnvelopeContext,
  input: {
    recipientDid: string
    recipientDeviceId: string
    groupDid: string
    kind: string
    envelope: Record<string, unknown>
    originContextJson?: string
  },
): void {
  ctx.storage.enqueueDeviceEnvelope({
    recipientDid: input.recipientDid,
    recipientDeviceId: input.recipientDeviceId,
    groupDid: input.groupDid,
    kind: input.kind,
    envelopeJson: JSON.stringify(input.envelope),
    ...(input.originContextJson !== undefined ? { originContextJson: input.originContextJson } : {}),
    attempts: 0,
    nextAttemptAt: ctx.acceptedAt,
    enqueuedAt: ctx.acceptedAt,
  })
}

/** §12.5 的一封 `group.incoming`。`body.group_cipher_object` 是被接受的 `send` 正文里那
 *  一颗，**逐字节**抄（§12.6 第 2 条禁止重编码、重排）。 */
function incomingEnvelope(
  ctx: EnvelopeContext,
  recipientDid: string,
  recipientDeviceId: string,
  body: Record<string, unknown>,
): Record<string, unknown> {
  const meta = ctx.meta
  const auth = preservedAuth(ctx)
  return {
    jsonrpc: '2.0',
    method: GROUP_INCOMING_P6,
    params: {
      meta: {
        profile: GROUP_E2EE_PROFILE,
        security_profile: INCOMING_SECURITY_PROFILE,
        // §12.5 L1486：发送方那一对**原样**保留。
        sender_did: meta.sender_did,
        sender_device_id: meta.sender_device_id,
        target: { kind: 'agent', did: recipientDid },
        recipient_device_id: recipientDeviceId,
        // §12.5 L1487：三个被接受的字段原样保留。
        message_id: meta.message_id,
        operation_id: meta.operation_id,
        content_type: meta.content_type,
        // 信封自己的 created_at 是**投递时刻**，提交时那个进 origin_context（§13.6 L1677）。
        created_at: ctx.acceptedAt,
      },
      ...(auth !== undefined ? { auth } : {}),
      body,
    },
  }
}

/**
 * `group.e2ee.send` 被接受：给每一条 active leaf 一封 `group.incoming`。
 *
 * §12.5 L1491 逐字："The Group Host emits one independent envelope per current device leaf.
 * All such envelopes carry the same ordering fields, receipt, and MLS `PrivateMessage`;
 * only `meta.target.did` and `meta.recipient_device_id` vary by leaf."
 *
 * **发送方自己的 leaf 也在其中**——那一条没有例外，而"同一颗 `PrivateMessage` 发给每条
 * leaf"的读法下，发送设备多收一份自己的消息是它可以按 `message_id` 去重的正常现象。
 */
export function emitIncomingEnvelopes(
  ctx: EnvelopeContext,
  input: {
    groupDid: string
    leaves: readonly StoredGroupLeaf[]
    cipher: Record<string, unknown>
    receipt: Record<string, unknown>
    groupStateVersion: string
    groupEventSeq: string
  },
): void {
  const body: Record<string, unknown> = {
    group_did: input.groupDid,
    group_state_version: input.groupStateVersion,
    group_event_seq: input.groupEventSeq,
    accepted_at: ctx.acceptedAt,
    group_receipt: input.receipt,
    group_cipher_object: input.cipher,
  }
  const contextJson = JSON.stringify(originContext(ctx.meta))
  for (const leaf of input.leaves) {
    enqueue(ctx, {
      recipientDid: leaf.memberDid,
      recipientDeviceId: leaf.memberDeviceId,
      groupDid: input.groupDid,
      kind: ENVELOPE_INCOMING,
      envelope: incomingEnvelope(ctx, leaf.memberDid, leaf.memberDeviceId, body),
      originContextJson: contextJson,
    })
  }
}

/**
 * `group.e2ee.add` 被接受：commit 给加完之后的每一条 active leaf，welcome 给新 leaf。
 *
 * `leaves` 是**处理器写完之后**的投影（含新 leaf），所以调用点必须在 `upsertGroupLeaf`
 * 之后取一次。
 */
export function emitAddEnvelopes(
  ctx: EnvelopeContext,
  input: {
    groupDid: string
    leaves: readonly StoredGroupLeaf[]
    groupStateRef: Record<string, unknown>
    cryptoGroupId: string
    epoch: string
    memberDid: string
    memberDeviceId: string
    commitB64u: string
    welcomeB64u: string
    ratchetTreeB64u: string
  },
): void {
  // §7.6 L665：同一次密码学结果**逐叶**的那几份 MAY 共用一个 `notice_id`，因为每台设备只
  // 按 `(group_did, notice_id)` 去重自己收到的那些。共用一个更省，也让"这是同一次 Add"
  // 在日志里一眼可辨。
  const noticeId = newId()
  const messageId = newId()
  const operationId = newId()

  const commitBody: Record<string, unknown> = {
    notice_id: noticeId,
    notice_type: 'commit-delivery',
    group_did: input.groupDid,
    group_state_ref: input.groupStateRef,
    crypto_group_id_b64u: input.cryptoGroupId,
    epoch: input.epoch,
    subject_did: input.memberDid,
    subject_device_id: input.memberDeviceId,
    // §7.6 L673：Add 用被加进来的那台，状态 `active`。
    subject_status: 'active',
    commit_b64u: input.commitB64u,
  }
  for (const leaf of input.leaves) {
    enqueue(ctx, {
      recipientDid: leaf.memberDid,
      recipientDeviceId: leaf.memberDeviceId,
      groupDid: input.groupDid,
      kind: ENVELOPE_COMMIT,
      envelope: {
        jsonrpc: '2.0',
        method: GROUP_E2EE_NOTICE,
        params: {
          meta: noticeMeta(leaf.memberDid, leaf.memberDeviceId, input.groupDid, messageId, operationId, ctx.acceptedAt),
          body: commitBody,
        },
      },
    })
  }

  // §12.4：welcome **只**给被加入的那一台，MUST NOT 发给 sibling。
  enqueue(ctx, {
    recipientDid: input.memberDid,
    recipientDeviceId: input.memberDeviceId,
    groupDid: input.groupDid,
    kind: ENVELOPE_WELCOME,
    envelope: {
      jsonrpc: '2.0',
      method: GROUP_E2EE_NOTICE,
      params: {
        meta: noticeMeta(input.memberDid, input.memberDeviceId, input.groupDid, messageId, operationId, ctx.acceptedAt),
        body: {
          notice_id: noticeId,
          notice_type: 'welcome-delivery',
          group_did: input.groupDid,
          group_state_ref: input.groupStateRef,
          crypto_group_id_b64u: input.cryptoGroupId,
          epoch: input.epoch,
          subject_did: input.memberDid,
          subject_device_id: input.memberDeviceId,
          // §7.6 L673：与 commit 那一份同一个 device，同一条 body 形状。**不能省**——
          // `anp` 的规范线格式向量（`testdata/group_e2ee/p6_v2_wire_vectors.json` 的
          // `notice_notification`，就是一条 welcome-delivery）里有这一位，且 crate 的
          // `V2E2eeNotice` 把它当必填、`validate_notice_outer` 对 welcome 要求它等于
          // `active`。少了它，按 crate 写的接收端连 body 都反序列化不出来。
          subject_status: 'active',
          welcome_b64u: input.welcomeB64u,
          ratchet_tree_b64u: input.ratchetTreeB64u,
        },
      },
    },
  })
}

/**
 * `group.e2ee.remove` 被接受：commit 给每一条**保留的** leaf，final notice 给被移除的那一条。
 *
 * 次序是这条方法的全部要点（§12.3 L1455 与 §6.1）：被移除 leaf 的最终通知 **MUST NOT**
 * 越过 Host 仍打算投的应用信封，所以它必须排在那条 leaf 队里所有既有行**之后**。入队是
 * 追加，`seq` 自增，于是"现在就写"正好落在队尾——而那台设备此后再不会收到新的应用信封
 * （它的 leaf 已经 `terminal`，`emitIncomingEnvelopes` 不会再看见它）。
 *
 * 我们**没有**在这里为被移除的 leaf 取消已入队的应用信封：§12.3 L1455 给两条路，我们选
 * **SHOULD** 那条（先投完，再投最终通知），理由写在 [e2ee-group.md] §6.1。
 */
export function emitRemoveEnvelopes(
  ctx: EnvelopeContext,
  input: {
    groupDid: string
    retainedLeaves: readonly StoredGroupLeaf[]
    subjectDid: string
    subjectDeviceId: string
    groupStateRef: Record<string, unknown>
    cryptoGroupId: string
    epoch: string
    commitB64u: string
  },
): void {
  const noticeId = newId()
  const messageId = newId()
  const operationId = newId()

  const body: Record<string, unknown> = {
    notice_id: noticeId,
    notice_type: 'commit-delivery',
    group_did: input.groupDid,
    group_state_ref: input.groupStateRef,
    crypto_group_id_b64u: input.cryptoGroupId,
    epoch: input.epoch,
    subject_did: input.subjectDid,
    subject_device_id: input.subjectDeviceId,
    // §7.6 L673：Remove 用被移除的那一台，状态 `removed`。
    subject_status: 'removed',
    commit_b64u: input.commitB64u,
  }

  for (const leaf of input.retainedLeaves) {
    enqueue(ctx, {
      recipientDid: leaf.memberDid,
      recipientDeviceId: leaf.memberDeviceId,
      groupDid: input.groupDid,
      kind: ENVELOPE_COMMIT,
      envelope: {
        jsonrpc: '2.0',
        method: GROUP_E2EE_NOTICE,
        params: {
          meta: noticeMeta(leaf.memberDid, leaf.memberDeviceId, input.groupDid, messageId, operationId, ctx.acceptedAt),
          body,
        },
      },
    })
  }

  // 最后写：`seq` 因此是这条队列里最大的一条。
  enqueue(ctx, {
    recipientDid: input.subjectDid,
    recipientDeviceId: input.subjectDeviceId,
    groupDid: input.groupDid,
    kind: ENVELOPE_FINAL_NOTICE,
    envelope: {
      jsonrpc: '2.0',
      method: GROUP_E2EE_NOTICE,
      params: {
        meta: noticeMeta(input.subjectDid, input.subjectDeviceId, input.groupDid, messageId, operationId, ctx.acceptedAt),
        body,
      },
    },
  })
}
