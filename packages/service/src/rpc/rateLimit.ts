// P5 §7.3 L598 的落点：`direct.e2ee.publish_prekey_bundle` 与 `get_prekey_bundle` 的限流。
//
// 原文只写了一句 MUST —— "Caller identity, rate limiting, and anti-abuse policies MUST be
// enforced using hop- and service-level authentication." —— 没有给数字、没有给算法、没有给
// 错误码，也没有说"哪几条方法"。三处都由本实现补：
//
//   - **范围**：只覆盖 §7.3 那一节管的这两条 Key 方法。那一节的标题是 "Server-side Bundle
//     distribution rules"，讲的是**发放 PreKey 材料**这件事本身；把整个服务都罩进来，
//     拒掉的会是规范没让拒的请求。
//   - **键**：见下面 `callerKeyOf`。
//   - **码**：`anp.rate_limited`（1011，P1 §10.3 L709）。它是公共段里唯一说这件事的码，
//     P5 §13 L1533–1545 的 4000 段里没有对应项——那一段全是关于材料的，没有一条说"你来得
//     太勤"。
//
// ## 为什么是令牌桶
//
// 这两条方法的正常节奏是**一阵一阵的**：发布一台设备的 Bundle 加一批 OPK 是一次突发，
// 然后很久不动；建链时 `get_prekey_bundle` 会连着来几次（每个对端一次）。固定窗口会在窗口
// 边界上放过两倍流量，并且把"刚刚那次突发"与"跨窗口的两次正常调用"判成同一件事。令牌桶
// 用一个容量就把两者分开了：突发只要有令牌就放行，持续速率由补充速度决定。
//
// ## 已知的弱点
//
// 桶按调用方分，而调用方身份在**同域明文**调用上只是一个自报字段（`meta.sender_did`，没有
// 任何东西证明它是它）。所以这个计数器挡得住"一个身份的洪泛"，挡不住"换一串 DID 的洪泛"；
// 跨域那一侧稍好——键取的是外层签名验出来的 `serviceDid`（P8 §6.2.2），一个域要伪造另一个
// 域的身份需要那颗私钥。真正的兜底在传输层（每个来源 IP 的连接数、`ANPIOCLI_MAX_BODY` 那种
// 体量闸门），不在这一层。
//
// ## 状态放在进程内存里
//
// v1 是单进程 + 内嵌 `node:sqlite`（[message-service.md](../..) §2），没有一个共享的计数器
// 可放。将来横向扩成多进程时，这张表要挪到共享存储上——那时"每个调用方一个桶"这件事会
// 变成"每个进程各算一份"，也就是实际额度乘以进程数。

/** 一个调用方一个桶。 */
interface Bucket {
  /** 当前令牌数，浮点：补充是连续的，不按整数秒跳。 */
  tokens: number
  /** 上次补充的时刻（epoch ms）。 */
  refilledAt: number
}

export interface RateLimitPolicy {
  /** 桶的容量，也就是一次突发最多能放多少个请求。 */
  burst: number
  /**
   * 每分钟补多少令牌。用"每分钟"而不是"每秒"是因为它从配置来，而 `ANPIOCLI_*` 那一族都是
   * 正整数（`config.ts` 的 `parsePositive`）：写成每秒就会需要一个 `0.5` 这样的值，于是
   * 每个部署都得先解释一遍浮点。`≥ 1` 也保证了下面的 `retryAfterSeconds` 不会除以 0。
   */
  perMinute: number
}

export interface RateLimitDecision {
  allowed: boolean
  /**
   * 拒绝时离下一次有令牌还有多少秒（向上取整，至少 1）。`Retry-After` 与
   * `error.data.retry_after` 都用它——P5 §13 L1545 要求错误响应"尽量"给出
   * `retryable`，而一个不说什么时候能再来的 `retryable: true` 让调用方只能盲重试。
   */
  retryAfterSeconds: number
}

/**
 * 令牌桶记分板。
 *
 * 时间不从 `Date.now()` 取，而是每次 `take` 由调用方给——一次请求一个时刻，与
 * `dispatch.ts` 的 `now()` 同一个理由。同一次请求里两次读时钟会得到两个时刻，而这个类里
 * 所有判断都是差值的判断，混用两个来源就没有"一次调用一个时刻"可言了。
 */
export function createRateLimiter(policy: RateLimitPolicy) {
  const buckets = new Map<string, Bucket>()
  const perSecond = policy.perMinute / 60

  /**
   * 一次机会。允许则扣一枚令牌，拒绝则**不扣**（并算出还差几秒）。
   *
   * 桶空时不更新时间戳：那次补充要等到有令牌可补时才算数，否则一个被持续打的桶会因为每次
   * 都刷新 `refilledAt` 而永远补不满——那是"拒绝"变成了"永远拒绝"。
   */
  function take(key: string, atMs: number): RateLimitDecision {
    const bucket = buckets.get(key) ?? { tokens: policy.burst, refilledAt: atMs }
    const elapsed = Math.max(0, atMs - bucket.refilledAt) / 1000
    const tokens = Math.min(policy.burst, bucket.tokens + elapsed * perSecond)
    if (tokens < 1) {
      buckets.set(key, { tokens, refilledAt: bucket.refilledAt })
      const deficit = 1 - tokens
      return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil(deficit / perSecond)) }
    }
    buckets.set(key, { tokens: tokens - 1, refilledAt: atMs })
    return { allowed: true, retryAfterSeconds: 0 }
  }

  return { take }
}

export type RateLimiter = ReturnType<typeof createRateLimiter>

/**
 * 这次调用按**谁**计数。
 *
 * 优先用外层认证验出来的 `serviceDid`（P8 §6.2.2）：那是这份部署里**唯一**一个别人伪造
 * 不了的身份——它由 `Signature-Input` 的 `keyid` 解析出来，而那个 DID 文档里必须有对应的
 * 公钥。同域明文调用没有 `Signature-Input`，`verifyOuterIdentity` 交回
 * `{ kind: 'absent' }`，于是退到 `meta.sender_did`。
 *
 * 退回去的那一档**不是认证**——§7.3 L598 要的是 "enforced using hop- and service-level
 * authentication"，而同域没有 hop 认证可依据。它挡的是"一个身份发得太快"，不是"有人冒充
 * 这个身份"。文件头写了这条缺口，`docs/design/e2ee-direct.md` §9 也记着一条：等跨域那一侧
 * 成为 Key 方法的主路径之后，这里该只认认证出来的身份。
 *
 * `sender_did` 由方法表的 `requiredMeta` 保证存在（调用点在 `checkMethod` 之后），所以
 * 这里没有第三条"没身份"的分支——真没有的话，那次调用根本到不了这里。
 */
export function callerKeyOf(authenticatedServiceDid: string | undefined, senderDid: string | undefined): string {
  if (authenticatedServiceDid !== undefined) return `service:${authenticatedServiceDid}`
  return `did:${senderDid ?? ''}`
}
