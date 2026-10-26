// P3 私聊：`direct.send` 的落库。
//
// 分两件事看：正文能不能收（`validatePayloadBody`，与群消息共用，见 `payload.ts`）与收下
// 之后写什么（`storeDirectMessage`）。两者都不看信封、不验签——那些是 §3 与 §5 的事，
// 这里拿到的已经是解析过、认证过的东西。
//
// 写库发生在 `acceptOperation` 的 `perform` 里，所以这里**不得**自己开事务、
// 也不得在写之前做任何可能失败的 I/O（一次网络往返会让并发写在锁里等）。
//
// 跨域那一跳（P8 §3.2）在**调用本模块之前**就已经做完了，而且是事务外面做的：目标不在
// 本服务上时，`relayed` 带着对端的答复进来，这里只记台账、不写投递。转发本身不属于这个
// 文件——它连一个字节都不该知道。

import { subjectOf, type AnpAuth, type AnpMeta, type AnpParams } from '@anpio-cli/core'
import type { DeliveryRecord, Storage } from '../storage/types'
import { attachmentGrantsFor, insertAttachmentGrants } from './attachments'

// `direct.send` 的正文规则就是 P3 §6.3 那条负载互斥规则，与 P4 §7.6 逐字相同，所以它住在
// `payload.ts` 里，两个 Profile 共用一份。

/**
 * `direct.incoming` 的 `params`（P3 §7.2.3 L409–422）。
 *
 * `direct.incoming` 是**这一个方法名**：它是通知，不是请求，表不在方法表里（本服务
 * 收它、不服务它）。放在这里是因为它承载的是"这条 `direct.send` 被投递时是什么样"，
 * 与这个文件里其余的私聊语义是同一件事。
 */
export const DIRECT_INCOMING = 'direct.incoming'

export interface IncomingParamsInput {
  meta: AnpMeta
  /** 收件人。就是 `meta.target.did`（P3 §7.2.3 L414），但单独传进来：`meta.target` 的
   *  类型是可选的，而 §7.2.3 要这一项 MUST 在。调用方刚查过目标绑定，让它把那个已经
   *  非空的值交过来，比在这里再写一次 `?? ''` 更诚实。 */
  targetDid: string
  body: Record<string, unknown>
  auth?: AnpAuth
}

/**
 * 落库时就构造好，而不是推送时再拼：推送失败要重试，重试时原始请求早已不在手上，
 * 而这些字段**必须**与原消息一致。存下来还能让取件面（`sync.delta`）直接把它当载荷，
 * 不必重建。
 *
 * `auth` 原样带走（L420）：中间服务**不得**重签，重签会把业务原发者的证明换成
 * 这个服务的，跨域链条上"谁发的"就变了。
 *
 * 这个函数只写 §7.2.3 L411–418 点名的七个字段。设备 selector 不在其中：L421 要求 Base
 * 的通知 **MUST NOT** 出现它们，而 Base 的 `direct.send` 连收都不收（`forbiddenMeta`）。
 * 但 P5 的 `direct.incoming` 恰好相反——§10.7.1 L1401 要求它**原样保留**两个 selector。
 * 所以这两项按**在场**写：请求里没有（Base 不可能有）就不出现，有就照抄。两族各要一个
 * 正好相反的东西，靠同一个"来自 meta 的字段"表达，不需要在这里判断 profile。
 */
export function incomingParams(input: IncomingParamsInput): AnpParams {
  const { meta } = input
  const deviceSelectors = {
    ...(meta.sender_device_id !== undefined ? { sender_device_id: meta.sender_device_id } : {}),
    ...(meta.recipient_device_id !== undefined ? { recipient_device_id: meta.recipient_device_id } : {}),
  }
  return {
    meta: {
      profile: meta.profile,
      security_profile: meta.security_profile,
      sender_did: meta.sender_did,
      target: { kind: 'agent', did: input.targetDid },
      operation_id: meta.operation_id,
      message_id: meta.message_id,
      content_type: meta.content_type,
      ...deviceSelectors,
    },
    // 没有 `auth` 就不放这个键：一个 `undefined` 进去，JSON 序列化后整键消失、但内存里
    // 形状不同，取件面读出来的东西会随序列化时机变。
    ...(input.auth !== undefined ? { auth: input.auth } : {}),
    body: input.body,
  }
}

export interface StoreDirectInput {
  meta: AnpMeta
  body: Record<string, unknown>
  auth?: AnpAuth
  /**
   * 目标不在本服务上时，**对端的答复**（P8 §3.2）。
   *
   * 给了它，这次受理就只到"消息行 + 幂等记录"为止：投递行、outbox 与附件授权都是
   * **目标 ingress** 的事。§3.1 把 `direct.incoming` 定成"已被目标 ingress 接受"之后的
   * 那一跳，而收件人不在我们这儿，我们这边没有可投递的邮箱；附件对象同理，它落在对端
   * （§9.2 L570 的域服务代理模式）。返回的是对端那一份结果，不是我们拼的——调用方拿到的
   * `accepted_at` 必须是真的受理时刻，那只有对端知道。
   */
  relayed?: Record<string, unknown>
  /** RFC 3339。由调用方给，测试才好钉住这个值。 */
  acceptedAt: string
  /**
   * The delivery this call appended, once there is one.
   *
   * A callback rather than a return value because the caller is inside a transaction and
   * must not use it yet: the subscription push (realtime.md §8.1) happens **after** the
   * commit, and this is how the record gets out there. Nothing may be published from here —
   * a message the transaction then rolls back would have been pushed to a live client.
   *
   * Not called on the duplicate path: §8.2 L444–450's second send of one message appends no
   * delivery, so there is no new sequence and nothing to push.
   */
  onDelivery?: (record: DeliveryRecord) => void
}

/**
 * 写下一条私聊消息与收件人的投递记录，返回 §7.1.3 L366–372 的成功 `result`。
 *
 * 结果**以 DID 为范围**（L378）：不含逐设备的结果数组，所以这里只有一份投递记录。P5
 * §10.7 L1394 另外要求 v2 的应答带上 `recipient_device_id`——它也同样不是数组：一条
 * `direct.send` 只承载**一台**接收设备的密文（§3.7 L136 要求每台各自的密文带自己唯一的
 * id 对，所以逐设备投递是并列的若干次调用，不是一次调用里的若干段）。
 */
export function storeDirectMessage(storage: Storage, input: StoreDirectInput): Record<string, unknown> {
  const { meta } = input
  const targetDid = meta.target?.did ?? ''
  const messageId = meta.message_id ?? ''
  const senderDid = meta.sender_did ?? ''
  const conversationId = input.body.conversation_id
  // §10.7 L1394：回显 **MUST** 等于请求。所以这一项取自 `meta`（请求里写了什么就回什么），
  // 不是取自投递行——两者今天必然相同，但"回显等于请求"说的是请求。
  const deviceEcho =
    meta.recipient_device_id !== undefined ? { recipient_device_id: meta.recipient_device_id } : {}

  // §8.2 L444–450 的消息级重复识别，也就是流程图里 M1 →「按重复消息策略处理」那一格。
  // 本实现的策略跟 §9.1 L630 给操作级的那个一样：把已经在那儿的消息**报回去**，不再存
  // 第二份、也不再排第二条投递——重放一条通知与重放一个响应，对收件人是同一件事。
  //
  // 只有操作级未命中时才会走到这里（C4 的 `perform` 只在未命中时被调用），所以这正是
  // §9.2 L650 排在第二位的那种情形：另一个 `operation_id` 指着一个已收下的消息。照
  // §8.4 L465–466 走的调用方（重试时 `operation_id` 与 `message_id` 都不变）根本到不了
  // 这一行——它命中的是操作级。
  const existing = storage.message(senderDid, targetDid, messageId)
  if (existing !== undefined) {
    return {
      accepted: true,
      message_id: existing.messageId,
      // 回的是**这次**操作的 id：应答的对象是这次调用。§9.1 L630 要的是"等价结果"而不是
      // 逐字节相同，而必须跨重放稳定的是 `message_id` / `target_did` / `accepted_at`
      // ——它们都取自落库那一行。
      operation_id: meta.operation_id,
      target_did: existing.targetDid,
      accepted_at: existing.acceptedAt,
      ...deviceEcho,
      ...(existing.conversationId !== undefined ? { conversation_id: existing.conversationId } : {}),
    }
  }

  const acceptedAt = input.acceptedAt
  storage.insertMessage({
    messageId,
    senderDid,
    targetDid,
    profile: meta.profile,
    securityProfile: meta.security_profile,
    contentType: meta.content_type ?? '',
    bodyJson: JSON.stringify(input.body),
    ...(typeof conversationId === 'string' ? { conversationId } : {}),
    acceptedAt,
  })

  // §9.2 L656：承载附件清单的消息被受理之后，发送方侧系统 **MUST** 为每个附件创建一条
  // Access Grant。必须与消息行同一个事务——事务外面就会出现"消息收下了、附件还不能下载"
  // 的中间态，而那个中间态客户端判断不出来（它只知道消息成功了）。
  //
  // 上面那条重复消息的分支没有这一步，是对的：它的 Grant 在**第一次**受理时就已经落了，
  // 重放一条通知不会多长出一条授权。
  if (input.relayed !== undefined) {
    // 跨域那一档到此为止（见 `relayed` 的注释）：投递行、outbox 与附件授权都是目标
    // ingress 的事，而这次受理在我们这边只是"替谁转过一次"的台账——消息行与幂等记录。
    return input.relayed
  }

  insertAttachmentGrants(
    storage,
    attachmentGrantsFor({
      contentType: meta.content_type ?? '',
      securityProfile: meta.security_profile,
      body: input.body,
      messageId,
      targetDid,
      createdAt: acceptedAt,
    }),
  )

  // §7.2.3 的字段表只写一遍：投递行与（C13 的）群通知用的是**同一份** `params`，两处各
  // 拼一次就是将来某次改动只改了一边的入口。
  const params = incomingParams({
    meta,
    targetDid,
    body: input.body,
    ...(input.auth !== undefined ? { auth: input.auth } : {}),
  })

  // 投递行就是这条消息在我域内的**终点**：收件人住在本服务上，C7 的订阅面与取件面从这里
  // 把它交出去（`onDelivery` 在事务提交之后推送）。C11 之前这里还往 outbox 排一条
  // `direct.incoming`，由后台 worker 再发一次 HTTP——而那个 worker 遇到自家入口时是直接
  // 丢掉的，所以那一条从来只是白跑一趟数据库。§3.1 把 `direct.incoming` 定成"已被目标
  // ingress 接受"之后的那一跳，而这里正是那个 ingress：没有第二跳要发。
  // 收件人**不在**本服务上时走的是 `relayed` 那条早返回，本节整段不执行。
  const delivered = storage.appendDelivery({
    ownerDid: targetDid,
    messageId,
    method: DIRECT_INCOMING,
    paramsJson: JSON.stringify(params),
    acceptedAt,
    // P5 §10.7 L1391：这条密文只属于那**一台**接收设备。P3 消息没有这一项，于是它
    // 落成 NULL、推给账号下每一个连接——那正是 §7.2.3 L421 要求设备 selector 缺席的意思。
    // 值取自 `meta`：它与 `params` 里那个 `target` 是同一份请求的两个字段，而推给谁
    // 是**投递行**的属性，不是通知载荷的（§10.7.1 L1407 说 `direct.incoming` 只投给
    // `recipient_device_id`，而它怎么找到那个连接由这张表说）。
    ...(meta.recipient_device_id !== undefined ? { recipientDeviceId: meta.recipient_device_id } : {}),
  })
  input.onDelivery?.(delivered)

  // TODO6 §3.3 的写入路径 ②：一条私聊到达，就把发件人记进**收件人**的通讯录。
  //
  // 这是"认识一下"，不是"起个名字"——所以走 `rememberContact` 而不是 `upsertContact`：
  // 后者按 `contacts.put` 的规则（缺字段即清空）会把用户已经起好的备注抹掉，而这次来信
  // 本身没有对名字说任何话。两条路径分开，是为了让"谁有权改名字"在代码里看得见。
  //
  // 位置在 `relayed` 早返回**之后**：收件人不在本服务上时这里整段不执行，因为那条消息
  // 的投递行、以及随之而来的这行通讯录，都是**目标 ingress** 的事——它自己会记。
  // 也因为在事务里：消息落库与"记住了这个人"同生共死，不会出现"消息在、人不在"。
  storage.rememberContact({
    ownerDid: targetDid,
    subject: subjectOf(senderDid),
    did: senderDid,
    at: acceptedAt,
  })

  return {
    accepted: true,
    message_id: messageId,
    operation_id: meta.operation_id,
    target_did: targetDid,
    accepted_at: acceptedAt,
    ...deviceEcho,
    // §7.1.3 L374–376：`conversation_id` 是 MAY，有就原样回。
    ...(typeof conversationId === 'string' ? { conversation_id: conversationId } : {}),
  }
}
