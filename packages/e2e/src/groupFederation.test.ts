// TODO4 §A3 —— 两台真服务，一次真的跨域 `group.send`。
//
// B1b 把三族都接进了中继（`RELAYED_METHODS`），但那条路上的"对端"一直是个 stub：它回答
// "文档指向我"或"文档指向别处"，不真解析、不起第二个服务（`dispatch.test.ts` 里那段
// `a group call whose group lives elsewhere`）。这一条把 stub 换成第二台真的 `AgentXAgent`，
// 走的是同一条中继、同一套 DID 解析、同一个 `egress`，只有"DID 文档谁托管"仍是玩具主机。
//
// **为什么不用 `connectx group send`。** 那条命令解析的是**群 DID**（`groupChannel` →
// `discover(groupDid)`），于是它直接把请求 POST 到群自己的域——这是 P2 §9.2 的地址发现，
// 没有中继什么事。中继要的是**请求打到了 A，目标却在 B**：调用方把自己域的服务当作入口
// （`meta.target.did` 是群 DID，`meta.target.kind` 是 `group`），由 A 的 `relayFor` 解析群
// 文档、发现端点不是自己，再把原始方法转发给 B。所以下面手工搭一个指向 A 的 `Channel`，
// 复用 `call` / `senderFor` / `policyFor` 这三个真客户端件——它们才是要被验的客户端路径。
//
// **外层签名故意没走。** `egress` 不配 `HttpSigner`：它的 `keyid` 要指向本服务的 DID 文档，
// 而那份文档不在本服务手里（TODO4 §C2，由 awiki 托管），e2e 里没有一处能解析出它，签了也
// 验不过。P8 §2.3 对这种调用的处置就是"按本地调用处理"——业务层的 `origin_proof`（由 alice
// 真签）照旧是唯一的授权依据，也是本条要验的东西。外层那半有它自己的单元测试。

import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { didToUrl, verifyObjectProofDetailed } from '@agentx/core'
import { call, policyFor, senderFor, type Channel } from '../../cli/src/commands/channel'
import { runGroup } from '../../cli/src/commands/group'
import { captureStdout, startFederatedWorld, type FederatedWorld } from './harness'

let world: FederatedWorld

beforeAll(async () => {
  world = await startFederatedWorld()
})

afterAll(async () => {
  await world?.stop()
})

/** 一次 `--json` 调用的输出就是它印的那一段 JSON——命令的对外契约，读它比读某个内部
 *  返回值更接近"调用方看到了什么"（`harness.ts` 的 `captureStdout` 注释）。 */
function jsonOf(out: string): Record<string, unknown> {
  return JSON.parse(out) as Record<string, unknown>
}

/** 用**对端会用的那个地址**取群文档：`didToUrl` 推出来的路径，dev-host 那条口把 https 换成
 *  http（`resolveDid.ts` 的 `documentUrl` 对 `AGENTX_DID_DEV_HOSTS` 里的主机做的事）。
 *  这里不调私有函数，是因为本条要验的正是"那个 URL 上真的有一份文档"。 */
async function fetchGroupDocument(groupDid: string): Promise<Record<string, unknown>> {
  const url = didToUrl(groupDid).replace(/^https:/, 'http:')
  const response = await fetch(url, { headers: { accept: 'application/did+json' } })
  expect(response.status).toBe(200)
  return (await response.json()) as Record<string, unknown>
}

describe('a group.send whose group lives in another domain (TODO4 A3)', () => {
  it('forwards into the group\'s own domain, and the receipt verifies back in the sender\'s', async () => {
    // carol 住 B 域（群的 Host），alice 住 A 域。两人共用同一个玩具 DID 主机——"DID 文档挂在
    // 哪"不是本条要测的东西；两个域的区分在各自服务条目的**端口**上。
    const carol = await world.createAgent('carol', world.b)
    const alice = await world.createAgent('alice', world.a)

    // 群建在 B 域，所以群 DID 落在 B 的命名空间里。
    const created = await captureStdout(() => runGroup({ ...carol.values, json: true }, 'create', []))
    const groupDid = jsonOf(created.out).group_did as string
    expect(groupDid.startsWith(`${world.b.config.serviceDid}:g:`)).toBe(true)

    // alice 先加入。这一步是直连 B 的（CLI 的地址发现），不是本条要验的那一跳；它建的是
    // "alice 在 B 的名册上是 active"这个前提，少了它 `group.send` 会被 B 以权限回绝。
    const joined = await captureStdout(() => runGroup({ ...alice.values, json: true }, 'join', [groupDid]))
    const joinReceipt = jsonOf(joined.out).group_receipt as Record<string, unknown>
    expect(joinReceipt.subject_method).toBe('group.join')

    // 真正的那一跳：请求交给 **alice 自己域的服务 A**，目标却是 B 域的群。
    const sender = await senderFor(alice.values)
    const aServiceDid = world.a.config.serviceDid
    const channel: Channel = {
      sender,
      target: {
        identity: aServiceDid,
        serviceId: `${aServiceDid}#anp-message-service`,
        endpoint: world.a.rpcEndpoint,
        serviceDid: aServiceDid,
        hintedProfiles: [],
        hintedSecurityProfiles: [],
      },
      // 本机 + 明文 http：`127.0.0.1` 是 loopback，`policyFor` 自己就把它放进两处放宽
      // （`relaxedHosts` 的规则），所以 A 与玩具主机的地址都过得了闸。
      options: policyFor(['127.0.0.1'], alice.values),
    }
    const messageId = 'm-cross-domain-1'
    const response = await call(channel, {
      method: 'group.send',
      profile: 'anp.group.base.v2',
      target: { kind: 'group', did: groupDid },
      body: { text: 'hello from A' },
      messageId,
      contentType: 'text/plain',
    })

    // A 的答复就是 B 的答复，原样带回（§3.2 的"转发原始方法"）——所以这一条同时也说明
    // A 没有把这次调用误判成"住在这里的群"。
    expect('result' in response).toBe(true)
    if (!('result' in response)) throw new Error(`A refused the relayed send: ${JSON.stringify(response)}`)
    const result = response.result
    expect(result.accepted).toBe(true)
    expect(result.message_id).toBe(messageId)

    // ---- 第一条：转发真的发生 ----
    // B 有群、有名册、有这条消息，正文还是原来那份（中继没有在中间重建它）。
    expect(world.b.storage.group(groupDid)).toBeDefined()
    expect(world.b.storage.groupMember(groupDid, alice.did)).toBeDefined()
    const stored = world.b.storage.message(alice.did, groupDid, messageId)
    expect(stored).toBeDefined()
    expect(JSON.parse(stored!.bodyJson)).toEqual({ text: 'hello from A' })

    // ---- 第三条：A 域本地一个群行都没落 ----
    // 不只是群行：名册与消息行也一条都不该有。跨域受理在 A 这一侧只写幂等台账
    // （`acceptOperation`），群的状态整个住在 B。
    expect(world.a.storage.group(groupDid)).toBeUndefined()
    expect(world.a.storage.groupMembers(groupDid)).toEqual([])
    expect(world.a.storage.message(alice.did, groupDid, messageId)).toBeUndefined()

    // ---- 第二条：B 签的回执，在 A 域用 B 域发布的群文档验得过 ----
    // 回执是**别的域**要依赖的东西，所以它必须能被离开 B 域的地方验（§7.9 L516）——这正是
    // A5 一律签名的理由。这里把 issuer 文档换成从 B 真的取回来的那一份：不是 B 手里的对象，
    // 是网络上那份。
    const receipt = result.group_receipt as Record<string, unknown>
    expect(receipt.subject_method).toBe('group.send')
    expect(receipt.actor_did).toBe(alice.did)
    expect(receipt.group_did).toBe(groupDid)
    // 事件序落在加入之后一位：这个数只有 B 数得出来，A 手上没有任何东西能编出它。
    expect(Number(receipt.group_event_seq)).toBe(Number(joinReceipt.group_event_seq) + 1)

    const groupDocument = await fetchGroupDocument(groupDid)
    expect(groupDocument.id).toBe(groupDid)
    const outcome = verifyObjectProofDetailed({
      document: receipt,
      issuerDid: groupDid,
      issuerDocument: groupDocument,
    })
    expect(outcome).toMatchObject({ ok: true })
    // 验出来的那一支要挂在这个群自己的 DID 下（groups.md §7.9 L516）。
    expect(outcome.ok && outcome.verificationMethod.startsWith(`${groupDid}#`)).toBe(true)
  })
})
