// TODO7 §5 —— 两台**真**服务，一次真的跨域 `group.send`。
//
// 这一条原来长在 `packages/e2e`（`groupFederation.test.ts`），随 TS 客户端退役整包删掉了。
// TODO7 §5 说它的判据是"等中继那半有了别处的覆盖再谈搬"，而搬的时候**不能照抄**：
// 那一份的驱动是 TS 客户端命令（`packages/cli` 的 `call` / `senderFor` / `runGroup`），
// 那半边已经不在了。搬过来的是**服务端那半边**——两台真 `createServer`、真 HTTP、真群文档
// 解析，驱动改成 core 的 `buildMessageRequest`。
//
// 它补的是别的用例补不了的那一格：
//   - `rpc/dispatch.test.ts` 的 "a group call whose group lives elsewhere" 验的是**路由**
//     （谁被问了、什么被原样带回去），对端是个回答固定值的 stub；
//   - `federation/forward.test.ts` 验的是中继自己的三分支，对端也是 stub；
//   - 这里对端是**第二台真的 `AnpioAgent`**：A 的 `relay` 要真的去取 B 的群文档
//     （`http://127.0.0.1:<portB>/g/<id>/did.json`）、真的把请求 POST 过去，B 真的受理、
//     真的把回执带回来。stub 换成真服务之后，唯一还是"玩具"的是 DID 文档的来源——
//     两台服务都用内联解析器，因为"文档挂在哪个 host"不是这一条要测的东西。
//
// **外层签名故意没走。** 发给 A 的请求不带 ANP-02 的外层身份头（A 配了 `egress` 也不签，
// 没有 `ANPIOCLI_KEY_FILE`）。P8 §2.3 对这种调用的处置就是"按本地调用处理"——业务层的
// `origin_proof`（由 alice 真签）照旧是唯一的授权依据，也正是本条要验的东西。外层那半有
// 它自己的单元测试（`federation/outer.test.ts`）。

import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createServer as createNetServer } from 'node:net'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  DidKeyResolver,
  buildMessageRequest,
  buildOriginProofAuth,
  createAnpIdentity,
  ed25519OriginProofSigner,
  type AnpMeta,
  type AnpRequest,
  type KeyResolver,
  type LocateOptions,
} from '@anpio-cli/core'
import { loadConfig, type Config } from '../config'
import { createEgress } from './egress'
import { createRelay } from './forward'
import { createHttpNonceStore } from './nonces'
import { createServer, RPC_PATH, type RpcHandler, type RpcResponse, type RunningServer } from '../http/server'
import { openObjectStore } from '../objects'
import { createDispatch } from '../rpc/dispatch'
import { groupDidDocument } from '../rpc/groupDidDocument'
import { openStorage } from '../storage/sqlite'
import { buildServiceEntry } from '../well-known'
import type { Storage } from '../storage/types'

/** 一个固定的时钟：`origin_proof` 的窗口是签出来的，服务端按自己的 `now` 判，所以两台
 *  服务与签名方必须钉在同一个时刻上——不钉的话这一条会在真实时钟走过窗口之后开始红，
 *  而红的原因与"中继不通"长得一模一样。 */
const NOW = new Date('2026-10-01T12:00:00Z')
const NOW_SECONDS = Math.floor(NOW.getTime() / 1000)

/** carol 住 B 域（群的 Host），alice 住 A 域。两人不在同一个服务上，这正是跨域的前提。 */
const carol = createAnpIdentity('carol.example')
const alice = createAnpIdentity('alice.example')

/** 生产里文档来自对端自己的域；这里按 keyid 里的身份直接给一份，好让受理路径跑得起来
 *  又不起 DID host。两台服务看到的是同一张表——"文档谁托管"不是本条要测的东西。 */
const DOCUMENTS: Record<string, unknown> = {
  [carol.did]: carol.didDocument,
  [alice.did]: alice.didDocument,
}

function inlineResolver(documents: Record<string, unknown> = DOCUMENTS): KeyResolver {
  const base = new DidKeyResolver()
  return {
    resolve(identity: string, keyid: string, opts: LocateOptions = {}) {
      const bare = keyid.includes('#') ? keyid.slice(0, keyid.indexOf('#')) : keyid
      return base.resolve(identity, keyid, { ...opts, didDocument: documents[bare] })
    },
  }
}

/** 一个 OS 挑的空闲端口。`serviceDid` 里带着端口（群 DID 的前缀就是它），所以端口必须在
 *  `listen()` 之前就知道——`ANPIOCLI_LISTEN=…:0` 那种"绑定后再读"在这里来不及。 */
async function freePort(): Promise<number> {
  const probe = createNetServer()
  await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve))
  const address = probe.address()
  const port = typeof address === 'object' && address !== null ? address.port : 0
  await new Promise<void>((resolve) => probe.close(() => resolve()))
  return port
}

/** 一台真的 AnpioAgent，接线与 `main.ts` 逐条对应（少了三个后台 worker——本条不投递、
 *  不推、不定时刷新，所以它们不需要起来）。 */
interface Instance {
  config: Config
  storage: Storage
  server: RunningServer
  rpcEndpoint: string
  /** 直接调本服务的受理路径，不走网络。建群、加人这种"前提"用它，被验的那一跳走 HTTP。 */
  dispatch: RpcHandler
}

async function startInstance(port: number): Promise<Instance> {
  const config = loadConfig({
    ANPIOCLI_LISTEN: `127.0.0.1:${port}`,
    ANPIOCLI_DB: ':memory:',
    ANPIOCLI_PUBLIC_URL: `http://127.0.0.1:${port}`,
    ANPIOCLI_SERVICE_DID: `did:web:127.0.0.1%3A${port}`,
    // 联调豁免：这个主机允许解析到私有地址、允许明文 http。进白名单的方式是 dev hosts
    // 也**同时进 `allowedHosts`**（`config.ts` L248），所以一个变量管两道门。
    ANPIOCLI_DID_DEV_HOSTS: '127.0.0.1',
    ANPIOCLI_OBJECT_DIR: mkdtempSync(join(tmpdir(), `anpiocli-cross-domain-${port}-`)),
  })
  const storage = openStorage({ path: ':memory:' })
  const objects = openObjectStore({ directory: config.objectDir, maxBytes: 1024 * 1024 })
  const egress = createEgress({ config })
  const dispatch = createDispatch({
    config,
    storage,
    objects,
    relay: createRelay({ config, egress }),
    resolver: inlineResolver(),
    nonceStore: createHttpNonceStore(storage),
    now: () => NOW,
    log: () => {},
  })
  const server = createServer({
    config,
    handleRpc: dispatch,
    wellKnown: JSON.stringify(buildServiceEntry(config), null, 2),
    handleGroupDid: (groupDid) => {
      const document = groupDidDocument(storage, config, groupDid)
      return document === undefined ? undefined : JSON.stringify(document, null, 2)
    },
  })
  await server.listen()
  return {
    config,
    storage,
    server,
    rpcEndpoint: `${config.publicUrl}${RPC_PATH}`,
    dispatch,
  }
}

/** 把一次调用交给某台服务的受理路径，HTTP 层的那点包装读成 `{status, json}`。 */
async function call(instance: Instance, request: AnpRequest): Promise<RpcResponse & { json: RpcJson }> {
  const response = await instance.dispatch({
    body: JSON.stringify(request),
    headers: { 'content-type': 'application/json' },
    url: new URL(instance.rpcEndpoint),
    method: 'POST',
  })
  return {
    ...response,
    json: response.body === '' ? {} : (JSON.parse(response.body) as RpcJson),
  }
}

interface RpcJson {
  result?: Record<string, unknown>
  error?: { code: number; message: string; data?: { anp_code?: string } }
}

/** §7.1 L347–358 的最小合法策略。`open-join` 让 alice 自己加入，不必再演一遍邀请。 */
const GROUP_POLICY = {
  admission_mode: 'open-join',
  permissions: {
    send: 'member',
    add: 'admin',
    remove: 'admin',
    update_profile: 'admin',
    update_policy: 'owner',
  },
}

async function envelope(options: {
  method: string
  meta: AnpMeta
  body: Record<string, unknown>
  signer: { priv: Parameters<typeof ed25519OriginProofSigner>[0]; keyid: string }
  id?: string
}): Promise<AnpRequest> {
  const auth = await buildOriginProofAuth({
    method: options.method,
    meta: options.meta,
    body: options.body,
    signer: ed25519OriginProofSigner(options.signer.priv, options.signer.keyid),
    created: NOW_SECONDS - 60,
    expires: NOW_SECONDS + 3600,
  })
  return buildMessageRequest({
    id: options.id ?? 'req-1',
    method: options.method,
    meta: options.meta,
    body: options.body,
    auth,
  })
}

function meta(overrides: Partial<AnpMeta>): AnpMeta {
  return {
    profile: 'anp.group.base.v2',
    security_profile: 'transport-protected',
    sender_did: carol.did,
    target: { kind: 'group', did: 'did:web:unset.example:g:placeholder' },
    operation_id: 'op-1',
    ...overrides,
  }
}

let a: Instance
let b: Instance
let groupDid: string

beforeAll(async () => {
  // 端口先定，服务后起：`serviceDid` 里含端口，而 B 的群文档路由是从 `serviceDid` 推出来的。
  const [portA, portB] = [await freePort(), await freePort()]
  a = await startInstance(portA)
  b = await startInstance(portB)

  // 群建在 B 域，所以群 DID 落在 B 的命名空间里——这正是"请求打到 A、群却在 B"的前提。
  const created = await call(b, await envelope({
    method: 'group.create',
    meta: meta({ target: { kind: 'service', did: b.config.serviceDid } }),
    body: { group_policy: GROUP_POLICY },
    signer: carol,
  }))
  groupDid = String(created.json.result?.group_did)
  expect(groupDid.startsWith(`${b.config.serviceDid}:g:`)).toBe(true)

  // alice 加入。这一步是直连 B 的（她自己域的服务 A 不是群的 Host），建的是"alice 在 B 的
  // 名册上是 active"这个前提——少了它，下面那一跳会被 B 以 `group.not_member` 回绝，
  // 而回绝的原因就和"中继没通"分不开了。
  const joined = await call(b, await envelope({
    method: 'group.join',
    meta: meta({ target: { kind: 'group', did: groupDid }, sender_did: alice.did, operation_id: 'op-join' }),
    body: {},
    signer: alice,
  }))
  expect(joined.json.result?.group_receipt).toBeDefined()
})

afterAll(async () => {
  await a?.server.close()
  await b?.server.close()
  a?.storage.close()
  b?.storage.close()
})

describe('a group.send whose group lives in another domain (TODO7 §5)', () => {
  it('forwards into the group\'s own domain over real HTTP, and the receipt comes back', async () => {
    // 真正的那一跳：请求交给 **alice 自己域的服务 A**，目标却是 B 域的群。A 的 relay 要
    // 真的去取 B 的群文档（那一步是 HTTP）、真的把请求 POST 到 B，B 受理之后把回执原样带回来。
    const request = await envelope({
      method: 'group.send',
      meta: meta({
        target: { kind: 'group', did: groupDid },
        sender_did: alice.did,
        operation_id: 'op-send',
        message_id: 'm-1',
        content_type: 'text/plain',
      }),
      body: { text: 'hello from another domain' },
      signer: alice,
      id: 'req-send',
    })

    const response = await fetch(a.rpcEndpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(request),
    })
    expect(response.status).toBe(200)
    const json = (await response.json()) as RpcJson

    expect(json.error).toBeUndefined()
    // 回执是 **B** 发的：它的 `group_did` 指的是 B 命名空间里的那个群，proof 也由群的钥签。
    // 回执能把 B 的名字带回来，就说明这一趟真的走到了 B，而不是 A 自己编了一个。
    const receipt = json.result?.group_receipt as Record<string, unknown> | undefined
    expect(receipt?.group_did).toBe(groupDid)
    expect(receipt?.subject_method).toBe('group.send')
    expect(receipt?.proof).toBeDefined()
  })

  it('files nothing of its own: the group is the peer\'s, and A records none of it', async () => {
    // A 只是入口。它替 B 把请求送过去，但**不能**在本地留下一行群——那等于替对端记了一笔
    // 它自己的账（`dispatch.ts` 的"a group call whose group lives elsewhere"那一组单测
    // 钉的就是这条，这里再在真服务上验一遍：stub 骗得过路由，骗不过第二台真服务）。
    expect(a.storage.group(groupDid)).toBeUndefined()
    // 反过来 B 那边必须真的有这个群——不然上面那条断言只是因为"两台都空着"而通过。
    expect(b.storage.group(groupDid)).toBeDefined()
  })

  it('answers 1012, not a peer error, when the group\'s domain cannot be reached', async () => {
    // 群文档解不出来时是"这一趟没走通"，不是对端回的拒绝。用一个 A 够不着的主机名，
    // 撞的是 `federation/forward.ts` 里的 `unavailable`（1012 `anp.temporarily_unavailable`），
    // 不是任何 `group.*` 的码。
    //
    // 用 `group.send` 而不是 `group.get_info`：这一条要的是一趟**有状态的**转发，`group.send`
    // 正是那一支。`group.get_info` 现在也真的会转发（它以前不会——见下面那段），但它是无状态
    // 的，一趟够不着的读在那里没有"受理"可言，用它会把这个用例测的东西换掉。
    const request = await envelope({
      method: 'group.send',
      meta: meta({
        target: { kind: 'group', did: 'did:web:nowhere.invalid:g:gone' },
        sender_did: alice.did,
        operation_id: 'op-unreachable',
        message_id: 'm-gone',
        content_type: 'text/plain',
      }),
      body: { text: 'hello nowhere' },
      signer: alice,
      id: 'req-unreachable',
    })

    const response = await fetch(a.rpcEndpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(request),
    })
    const json = (await response.json()) as RpcJson
    expect(json.error?.data?.anp_code).toBe('anp.temporarily_unavailable')
    // 而且它**没在本地落库**：这一趟没被受理，所以 A 名下的投递一条都不该多出来。
    expect(a.storage.headSeq(alice.did)).toBe(0)
  })
})
