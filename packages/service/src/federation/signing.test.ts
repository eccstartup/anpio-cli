import { describe, expect, it } from 'vitest'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  createAnpIdentity,
  createNonceStore,
  DidKeyResolver,
  verifyHttpSignatureForServer,
  type NonceStore,
  type ResolvedIdentityKey,
} from '@anpio-cli/core'
import { parseSignatureInput } from '@anpio-cli/core/advanced'
import { loadConfig, didWebFor } from '../config'
import { createHttpSigner, loadHttpSigner } from './signing'

// 这一半的价值全在**与验签侧对得上**：单看签出来的字符串什么也证明不了。所以每个用例都
// 拿 core 的 `verifyHttpSignatureForServer`（也就是 `outer.ts` 第 8 步调的那一个）当真值。

const identity = createAnpIdentity('sender.example')
const METHOD = 'POST'
const TARGET = 'https://receiver.example/anp-im/rpc'
const BODY = JSON.stringify({ jsonrpc: '2.0', id: 'req-1', method: 'direct.send' })

function keyOf(): Promise<ResolvedIdentityKey> {
  // 内联文档对路径型 DID 是可信的（DID 自己提交了公钥指纹），所以这一步不起网络。
  return new DidKeyResolver().resolve(identity.did, identity.keyid, { didDocument: identity.didDocument })
}

async function verify(
  headers: Record<string, string>,
  options: { body?: string; url?: string; nonceStore?: NonceStore } = {},
) {
  const url = new URL(options.url ?? TARGET)
  return verifyHttpSignatureForServer({
    method: METHOD,
    path: url.pathname,
    authority: url.host,
    targetUri: url.href,
    search: url.search,
    headers,
    body: options.body ?? BODY,
    key: await keyOf(),
    ...(options.nonceStore !== undefined ? { nonceStore: options.nonceStore } : {}),
  })
}

describe('createHttpSigner', () => {
  it('signs a request the verifier accepts', async () => {
    const signer = createHttpSigner(identity.keyid, identity.priv)
    const headers = await signer.headers({ method: METHOD, url: TARGET, body: BODY, nonce: 'n-1' })
    expect(await verify(headers)).toEqual({ ok: true })
  })

  it('covers the body: a changed payload fails the content digest', async () => {
    // §3.1.2 L112 要求有消息体时必须覆盖 `content-digest`。这条用例是那句话本身。
    const signer = createHttpSigner(identity.keyid, identity.priv)
    const headers = await signer.headers({ method: METHOD, url: TARGET, body: BODY, nonce: 'n-2' })
    const outcome = await verify(headers, { body: JSON.stringify({ jsonrpc: '2.0', id: 'other' }) })
    expect(outcome.ok).toBe(false)
  })

  it('covers the target: the same body at another URI fails', async () => {
    const signer = createHttpSigner(identity.keyid, identity.priv)
    const headers = await signer.headers({ method: METHOD, url: TARGET, body: BODY, nonce: 'n-3' })
    expect((await verify(headers, { url: 'https://receiver.example/other' })).ok).toBe(false)
  })

  it('puts a full DID URL in keyid, which is what L82 requires', async () => {
    // 少了 fragment 的 `keyid` 指的不是一个验证方法，而第 7 步要按它取下被
    // `authentication` 授权的那把钥。
    const signer = createHttpSigner(identity.keyid, identity.priv)
    const headers = await signer.headers({ method: METHOD, url: TARGET, body: BODY, nonce: 'n-4' })
    const parsed = parseSignatureInput(headers['signature-input'] ?? '')
    expect(parsed.params.keyid).toBe(identity.keyid)
    expect(parsed.params.keyid).toContain('#')
  })

  it('produces an RFC 9421 labeled signature value', async () => {
    const signer = createHttpSigner(identity.keyid, identity.priv)
    const headers = await signer.headers({ method: METHOD, url: TARGET, body: BODY, nonce: 'n-5' })
    expect(headers['signature-input']).toMatch(/^sig1=\(/)
    expect(headers.signature).toMatch(/^sig1=:[A-Za-z0-9+/]+=*:$/)
    expect(headers['content-digest']).toMatch(/^sha-256=:[A-Za-z0-9+/]+=*:$/)
  })

  it('does not itself stop a replay, and says so by leaving it to the nonce store', async () => {
    // §2.2：验签成功**不是**重放防护。同一份请求走两遍都能验过，挡住第二遍的是对端的
    // `http_nonces`——这正是 `outer.ts` 第 8 步把 store 传进去的原因。
    const signer = createHttpSigner(identity.keyid, identity.priv)
    const headers = await signer.headers({ method: METHOD, url: TARGET, body: BODY, nonce: 'replayed' })
    const store = createNonceStore()
    expect((await verify(headers, { nonceStore: store })).ok).toBe(true)
    expect((await verify(headers, { nonceStore: store })).ok).toBe(false)
  })
})

describe('loadHttpSigner', () => {
  function keyFile(contents: string): string {
    const dir = mkdtempSync(join(tmpdir(), 'anpiocli-key-'))
    const path = join(dir, 'service.key')
    writeFileSync(path, contents)
    return path
  }

  const serviceDid = didWebFor('http://127.0.0.1:8787')
  const hex = Buffer.from(identity.priv).toString('hex')

  it('reads a hex key file and signs with it', async () => {
    const config = loadConfig({
      ANPIOCLI_KEY_FILE: keyFile(hex),
      ANPIOCLI_KEY_ID: `${serviceDid}#key-1`,
    })
    const signer = await loadHttpSigner(config)
    expect(signer?.keyid).toBe(`${serviceDid}#key-1`)
    // 同一把私钥，所以验签要能过——只不过内嵌的文档是 `identity.did` 的那份，而
    // `keyid` 挂在别的 DID 上。签名本身与 DID 无关，验钥才有关：这里直接对着身份验。
    const headers = await signer!.headers({ method: METHOD, url: TARGET, body: BODY, nonce: 'file-1' })
    const base = await verifyHttpSignatureForServer({
      method: METHOD,
      path: new URL(TARGET).pathname,
      authority: new URL(TARGET).host,
      targetUri: TARGET,
      search: '',
      headers,
      body: BODY,
      key: await keyOf(),
    })
    expect(base.ok).toBe(true)
  })

  it('reads a PEM key file too, the format `connectx --key` also takes', async () => {
    // 两种都是纯文本，认出哪一种只按开头走——同一个钥文件两边都能用。
    const der = Buffer.from(identity.priv)
    const pem = `-----BEGIN PRIVATE KEY-----\n${der.toString('base64')}\n-----END PRIVATE KEY-----\n`
    const config = loadConfig({
      ANPIOCLI_KEY_FILE: keyFile(pem),
      ANPIOCLI_KEY_ID: `${serviceDid}#key-1`,
    })
    const signer = await loadHttpSigner(config)
    const headers = await signer!.headers({ method: METHOD, url: TARGET, body: BODY, nonce: 'file-2' })
    expect((await verify(headers)).ok).toBe(true)
  })

  it('is absent when the deployment has no key, rather than failing', async () => {
    // `keyFile` 缺席是配置层明说的"这份部署不出站"。这不是错误，是另一种部署形态。
    expect(await loadHttpSigner(loadConfig({}))).toBeUndefined()
  })
})
