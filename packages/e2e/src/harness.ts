// 端到端脚手架：**真服务 + 真 CLI 命令 + 真 socket**。
//
// 「端到端」在本仓库里的口径，就是 TODO2 那条 B2 写的那个缺口：P4/P5/P6 各自都按方法级测过，
// 却从没串起来跑过一次。所以这里替掉的东西要尽可能少，且每一处替换都要说得出理由：
//
//   * **服务侧不替**：`loadConfig` 读环境、`createDispatch`、`createServer`、`createStreamSession`
//     与 `main.ts` 的接线一一对应（`main.ts` 里省略的两件——`relay` 与数据面——本用例用不到，
//     它们是跨域转发与附件上传）。这不是"照着 main.ts 抄"，是同一批模块的同一批参数。
//   * **客户端侧不替**：跑的是 `connectx` 自己的命令函数（`runMsg` / `runListen`），
//     真的去开来宾身份、真的签 `origin_proof`、真的走 WebSocket。身份存储用
//     `CONNECTX_HOME` 指到临时目录，这是 CLI 本来就支持的开关（`identity/paths.ts` 文件头）。
//   * **替掉的是"DID 文档谁托管"**：一台玩具 HTTP 主机，按 `didToUrl` 推出来的路径把文档发出去。
//     真实部署里这一步是 DID Server（例如 `awiki-open-server`）。它被替掉的唯一理由是
//     awiki 今天只肯发端点指向它自己的文档（TODO2 的 A7），拿它当主机就测不到"对端服务在别处"。
//
// 网络闸门按 `AGENTX_DID_DEV_HOSTS` 那条联调口开（`config.ts` 说得清楚：它把同一批主机同时
// 放进 `allowedHosts` / `allowPrivateHosts` / `allowInsecureTransport`），所以被放宽的只是
// "本机 + 明文 http"，允许清单本身仍是精确主机名。

import { mkdtempSync } from 'node:fs'
import { createServer as createHttpServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { didToUrl } from '@agentx/core'
import type { Config } from '../../service/src/config'
import { loadConfig } from '../../service/src/config'
import { createServer, RPC_PATH } from '../../service/src/http/server'
import { openObjectStore } from '../../service/src/objects'
import { createDispatch } from '../../service/src/rpc/dispatch'
import { openStorage } from '../../service/src/storage/sqlite'
import { createSubscriberRegistry } from '../../service/src/stream/registry'
import { createStreamSession } from '../../service/src/stream/session'
import { buildServiceEntry, type ServiceEntry } from '../../service/src/well-known'
import { buildConnector } from '../../cli/src/commands/auth'
import type { Values } from '../../cli/src/commands/auth'
import { storeLocation } from '../../cli/src/identity/paths'
import { initIdentity, recordRegistration } from '../../cli/src/identity/store'

/** 一整轮端到端要用的东西：一台玩具 DID 主机、一个真服务、两个真 CLI 身份。 */
export interface World {
  service: RunningService
  didHost: DidHost
  /** 临时目录：CLI 的身份库与服务的对象目录都在里面，收尾时整棵删掉。 */
  home: string
  /** 立一个 `connectx` 身份，并把它的文档挂到玩具主机上。 */
  createAgent(name: string): Promise<Agent>
  /** 关掉一切。幂等。 */
  stop(): Promise<void>
}

// ---- 玩具 DID 主机 ------------------------------------------------------------

/** 一台只做一件事的 HTTP 主机：按路径发 DID 文档。路径就是 `didToUrl` 推出来的那个，
 *  所以"文档挂在哪"不需要第二个约定——DID 自己说了。 */
export interface DidHost {
  /** `127.0.0.1:<port>`，也就是 `did:wba` 第一段里那个主机（解码后的样子）。 */
  host: string
  origin: string
  /** 把一份文档挂到这个 DID 的解析地址上。 */
  publish(did: string, document: unknown): void
  stop(): Promise<void>
}

async function startDidHost(): Promise<DidHost> {
  const documents = new Map<string, unknown>()
  const server = createHttpServer((req, res) => {
    const path = new URL(req.url ?? '/', 'http://did.invalid').pathname
    const document = documents.get(path)
    if (document === undefined) {
      res.writeHead(404, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ error: 'no document at this path' }))
      return
    }
    // `application/did+json`：`resolveDid` 只认这一种与 `application/json`
    // （`DID_DOCUMENT_MEDIA_TYPES`），换个拼法会被判成"取回来的不是文档"。
    res.writeHead(200, { 'content-type': 'application/did+json' })
    res.end(JSON.stringify(document))
  })
  await listen(server)
  const port = (server.address() as AddressInfo).port
  const host = `127.0.0.1:${port}`
  return {
    host,
    origin: `http://${host}`,
    publish(did, document) {
      documents.set(new URL(didToUrl(did)).pathname, document)
    },
    stop: () => close(server),
  }
}

// ---- 真服务 ------------------------------------------------------------------

export interface RunningService {
  config: Config
  baseUrl: string
  rpcEndpoint: string
  streamEndpoint: string
  stop(): Promise<void>
}

/**
 * 起一个真服务。**端口是预先定下的**，不是 `:0`——`config.publicUrl` 与 `config.serviceDid`
 * 都由它派生，而 `stream.hello` 报的就是 `serviceDid`，客户端会拿它跟 DID 文档里那条
 *  `serviceDid` 对（`listen.ts` 的握手）。用 `:0` 的话这两处会写着一个端口 0，不是"哪里不对"
 * 而是"看起来对、其实对不上一个真地址"。
 */
async function startService(home: string, didHost: string): Promise<RunningService> {
  const port = await reservePort()
  const baseUrl = `http://127.0.0.1:${port}`
  const config = loadConfig({
    AGENTX_LISTEN: `127.0.0.1:${port}`,
    AGENTX_PUBLIC_URL: baseUrl,
    // 一个进程一份状态，跑完即弃；对象落在临时目录里，与库是同一棵树。
    AGENTX_DB: ':memory:',
    AGENTX_OBJECT_DIR: join(home, 'objects'),
    // 本机 + 明文 http 的联调口。主机名是精确的，没有通配。
    AGENTX_DID_DEV_HOSTS: didHost.split(':')[0]!,
  } as NodeJS.ProcessEnv)

  const storage = openStorage({ path: config.dbPath })
  const objects = openObjectStore({ directory: config.objectDir, maxBytes: config.maxObjectBytes })
  // `main.ts` 的接线：受理落库后把那条投递交给订阅路。少了这一步，`msg listen` 收不到推送，
  // 而"收不到"会看起来像客户端的毛病。
  const registry = createSubscriberRegistry()
  const handleRpc = createDispatch({
    config,
    storage,
    objects,
    onDelivered: (record) => {
      registry.publish(record)
    },
  })
  const session = createStreamSession({
    serverDid: config.serviceDid,
    storage,
    registry,
    handleRpc,
    resolverOptions: config.didResolution,
  })
  const server = createServer({
    config,
    handleRpc,
    handleStream: (connection, request) => session.handlersFor(connection, request),
    wellKnown: JSON.stringify(buildServiceEntry(config), null, 2),
  })
  await server.listen()

  return {
    config,
    baseUrl,
    rpcEndpoint: `${baseUrl}${RPC_PATH}`,
    streamEndpoint: `${baseUrl}/anp-im/stream`,
    async stop() {
      session.closeAll('test over')
      await server.close()
      storage.close()
    },
  }
}

/** 服务自己的那条 `ANPMessageService` 条目，`id` 换成文档所有者的 DID——`buildServiceEntry`
 *  的注释点名要求嵌入方做这件事（它不知道自己住在谁的文档里）。 */
function serviceEntryFor(config: Config, ownerDid: string): ServiceEntry {
  return { ...buildServiceEntry(config), id: `${ownerDid}#anp-message-service` }
}

// ---- 真 CLI 身份 -------------------------------------------------------------

export interface Agent {
  agent: string
  profile: string
  did: string
  /** 这个身份的命令行开关。`runMsg` / `runListen` 收的就是它。 */
  values: Values
}

/**
 * 立一个真的 `connectx` 身份：真随机钥、真写进 keystore、真在 `identity.json` 里记下
 * "注册在哪个 DID 主机"——`buildConnector({requireRegistered: true})` 只认这个记录，
 * 代码里没有第二条给身份安一个主机的路。
 */
async function createAgent(input: {
  name: string
  didHost: string
  config: Config
  didHostServer: DidHost
}): Promise<Agent> {
  const profile = 'default'
  const location = storeLocation(input.name, profile)
  await initIdentity({ location, curve: 'ed25519', password: '', force: true })
  // 先记主机、再组合 DID：`host` 是 DID 的一部分（`did:wba:<host>:user:<agent>:<指纹>`），
  // 而它只能来自"哪台服务器收下了这把钥"这条记录。
  recordRegistration({ location, host: input.didHost })

  const values: Values = { agent: input.name, profile }
  // 文档要带一条 `ANPMessageService`，因为**接收方**的命令要按自己的 DID 找到入口
  // （`openChannel` → `discover`）。发送方不带也能跑，这里一视同仁——每个 agent 都在
  // 自己的文档里广告自己的入口，本来就是常态。
  const { connector } = await buildConnector(values, {
    requireRegistered: true,
    // 返回一个**数组**，不是 `DidDocumentServices` 那个联合；联合的另一种形态是"按 DID 算
    // 端点"，这里不需要。
    service: (did: string): ServiceEntry[] => [serviceEntryFor(input.config, did)],
  })
  const identity = await connector.getIdentity()
  input.didHostServer.publish(identity.did, identity.didDocument)
  return { agent: input.name, profile, did: identity.did, values }
}

// ---- 组装 --------------------------------------------------------------------

/** 起一整套：玩具主机 → 服务 → 两个身份（alice 发、bob 收）。 */
export async function startWorld(): Promise<World> {
  const home = mkdtempSync(join(tmpdir(), 'connectx-e2e-'))
  // 进程级的开关，所以 `vitest.config.ts` 把这个包的文件设成不并行：两个文件各指一个
  // `CONNECTX_HOME`，并行跑就会互相抢。
  process.env.CONNECTX_HOME = home

  const didHost = await startDidHost()
  const service = await startService(home, didHost.host)
  return {
    service,
    didHost,
    home,
    createAgent: (name) => createAgent({ name, didHost: didHost.host, config: service.config, didHostServer: didHost }),
    async stop() {
      await service.stop()
      await didHost.stop()
    },
  }
}

// ---- 小工具 ------------------------------------------------------------------

function listen(server: import('node:net').Server | import('node:http').Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject)
      resolve()
    })
  })
}

function close(server: import('node:net').Server | import('node:http').Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()))
  })
}

/** 挑一个空闲端口再交给服务。选端口而不是让服务绑 `:0` 的原因见 `startService`。 */
async function reservePort(): Promise<number> {
  const probe = createHttpServer()
  await listen(probe)
  const port = (probe.address() as AddressInfo).port
  await close(probe)
  return port
}

/** 接住一次调用打出来的 stdout。`runMsg` 的结果就是它印的那几行——这是命令的对外契约，
 *  不是中间状态，所以断言它比断言某个内部返回值更接近"用户看到了什么"。
 *
 *  两处都要接：`channel.ts` 的 `field()` 走 `console.log`，而 `msg listen` 的渲染器走
 *  `process.stdout.write`（`listen-view.ts` 说要避开 `console.log`，因为那是一条线协议）。
 *  只接后者会漏掉整条 `msg` 命令族的输出。 */
export async function captureStdout<T>(fn: () => Promise<T>): Promise<{ value: T; out: string }> {
  const chunks: string[] = []
  const originalWrite = process.stdout.write
  const originalLog = console.log
  const collect = (...args: unknown[]): void => {
    chunks.push(args.map((arg) => (typeof arg === 'string' ? arg : String(arg))).join(' ') + '\n')
  }
  process.stdout.write = ((chunk: unknown): boolean => {
    chunks.push(String(chunk))
    return true
  }) as typeof process.stdout.write
  console.log = collect as typeof console.log
  try {
    const value = await fn()
    return { value, out: chunks.join('') }
  } finally {
    process.stdout.write = originalWrite
    console.log = originalLog
  }
}

/** 等到 `check()` 说了话为止。用于"订阅先连上、再发消息"这种真正有先后的两件事——
 *  两边没有共同的时钟，只能等一个可观测的信号。 */
export async function until(check: () => boolean, what: string, timeoutMs = 10_000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (!check()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`)
    await new Promise((resolve) => setTimeout(resolve, 10))
  }
}
