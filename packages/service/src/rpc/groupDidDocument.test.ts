// B1b-A2 —— 群 DID 文档的形状与签名。
//
// 这一层要验的是"别的域拿到的到底是份什么东西"：验证方法在不在两处授权里、服务条目有没有
// 声明 `serviceDid`、以及那份自签证明在附录 B 的规则下验不验得过。所以这里有两条独立的
// 验证路径，各自钉住一件事：
//
//  - `verifyObjectProofDetailed(doc, doc)` —— 附录 B 的九步。它同时管签名、六个字段的
//    形状、以及"这颗钥被 `assertionMethod` 授权"。**这不是取巧**：群的文档证明与
//    `group_receipt.proof` 走的是同一个 Profile、同一个签名底（dataIntegrity.ts 的
//    `didDocumentProofPayload`），所以拿文档自己当 issuer 文档来验，就是 A5 的回执将来
//    要走的同一条路。
//  - `verifyDidDocument(doc, groupDid)` —— 核心解析层的判断。它对原生 `did:web` 跳过证明，
//    所以它钉的是**另一句话**：这份文档能被解析成这个 DID 的文档，与签名无关。

import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { parsePrivateKey, verifyDidDocument, verifyObjectProofDetailed } from '@agentx/core'
import { encodeMultibaseEd25519, ed25519PublicKey } from '@agentx/core/advanced'
import { loadConfig, type Config } from '../config'
import { RPC_PATH } from '../http/server'
import { openStorage } from '../storage/sqlite'
import type { Storage } from '../storage/types'
import {
  GROUP_KEY_FRAGMENT,
  buildGroupDidDocument,
  groupDidDocument,
  groupDidKeyId,
  groupServiceEntry,
} from './groupDidDocument'

const SERVICE = 'did:web:agentx.example'
const PUBLIC_URL = 'https://agentx.example'
const GROUP = `${SERVICE}:g:AAAAAAAAAAAAAAAAAAAAAA`
const CREATED = '2026-10-02T00:00:00Z'
/** 一个真实的 32 字节种子。写死而不是随机，是为了让"公钥等于这个种子的公钥"能成为一条
 *  字面断言，而不是拿被测代码自己推出来的值跟自己比。 */
const SEED_HEX = '0f'.repeat(32)

let storage: Storage
let config: Config

beforeEach(() => {
  storage = openStorage({ path: ':memory:' })
  config = loadConfig({ AGENTX_PUBLIC_URL: PUBLIC_URL, AGENTX_SERVICE_DID: SERVICE })
})

afterEach(() => {
  storage.close()
})

function insertGroup(groupDid: string): void {
  storage.insertGroup({
    groupDid,
    hostServiceDid: SERVICE,
    groupStateVersion: 1,
    groupEventSeq: 1,
    groupProfileJson: '{}',
    groupPolicyJson: '{}',
    createdAt: CREATED,
    creatorDid: 'did:web:alice.example',
  })
}

function build(): Record<string, unknown> {
  return buildGroupDidDocument({
    groupDid: GROUP,
    privateKeyHex: SEED_HEX,
    serviceEntry: groupServiceEntry(config, GROUP),
  })
}

describe('the group DID document (B1b-A2)', () => {
  it('publishes one verification method, authorized in BOTH authentication and assertionMethod', () => {
    const document = build()
    const keyid = groupDidKeyId(GROUP)

    expect(keyid).toBe(`${GROUP}#${GROUP_KEY_FRAGMENT}`)
    expect(document.id).toBe(GROUP)

    // 一条方法，不是两条：同一个 `keyid` 在两处出现是**同一颗钥的两种用途**，
    // 不是两颗钥。写成两条 verificationMethod 会让文档里出现两个 id。
    expect(document.verificationMethod).toEqual([
      {
        id: keyid,
        type: 'Multikey',
        controller: GROUP,
        publicKeyMultibase: encodeMultibaseEd25519(ed25519PublicKey(parsePrivateKey(SEED_HEX, 'ed25519').privateKey)),
      },
    ])
    // `authentication` 让它能作为群的身份被认证；`assertionMethod` 是
    // `group_receipt.proof` 的归处（groups.md §7.9 L516）。少任一条，A5 要么签不出合法的
    // 回执，要么签出来的回执在别处验不过。
    expect(document.authentication).toEqual([keyid])
    expect(document.assertionMethod).toEqual([keyid])

    expect(document['@context']).toContain('https://www.w3.org/ns/did/v1')
    expect(document['@context']).toContain('https://w3id.org/security/multikey/v1')
  })

  it('carries an ANPMessageService entry that declares serviceDid and names THIS group as its id', () => {
    const document = build()
    const service = document.service as Array<Record<string, unknown>>

    expect(service).toHaveLength(1)
    expect(service[0]).toMatchObject({
      // 服务条目住在被描述的那个 DID 的文档里，所以 id 是**群的** DID URL——`well-known.ts`
      // 里那份给不出文档所有者 id 的版本不能原样发出去。
      id: `${GROUP}#anp-message-service`,
      type: 'ANPMessageService',
      serviceEndpoint: `${PUBLIC_URL}${RPC_PATH}`,
      // P8 §6.2.1 L327：参与跨域的服务条目 MUST 声明 `serviceDid`。这条文档的全部意义就是
      // 让别的域据此找到我们（§5.2 L215–221），缺了它，找到的端点不知道属于谁签。
      serviceDid: SERVICE,
    })
  })

  it('self-signs the document, and the proof passes Appendix B against the document itself', () => {
    const document = build()

    // 九步全过：六个字段的形状、`verificationMethod` 的完整 DID URL、`created` 的 RFC 3339、
    // **`assertionMethod` 的授权**、以及签名本身。
    expect(verifyObjectProofDetailed({ document, issuerDid: GROUP, issuerDocument: document })).toEqual({
      ok: true,
      verificationMethod: groupDidKeyId(GROUP),
    })
  })

  it('covers the service entry: it is signed in, not appended after the fact', () => {
    const document = build()
    // `proof` 覆盖签的时候文档里已有的每个字段（ANP-03 §2.5.5）。这里改的是一个只在
    // `service` 里出现的值：如果签名发生在上服务条目之前，它就不会被发现。
    const service = document.service as Array<Record<string, unknown>>
    service[0].serviceEndpoint = 'https://evil.example/anp/rpc'

    expect(verifyObjectProofDetailed({ document, issuerDid: GROUP, issuerDocument: document })).toEqual({
      ok: false,
      reason: 'signature_invalid',
    })
  })

  it('resolves as the group DID document even though core skips the proof for did:web', () => {
    // 这句话是 A2 最容易被读反的地方：`documentProofPolicy` 对原生 `did:web` 直接返回
    // `skipped`，所以**去掉签名这段文档照样解析**。签名不是为了解析通过（见模块头）。
    const document = build()
    expect(() => verifyDidDocument(document, GROUP)).not.toThrow()

    const unsigned = build()
    delete unsigned.proof
    expect(() => verifyDidDocument(unsigned, GROUP)).not.toThrow()
  })

  it('keeps a present proof verifiable when the service DID is a did:wba', () => {
    // 服务 DID 是 `did:wba` 时群 DID 是 `did:wba:host:e1_…:g:<id>`：末段是群 id 而不是
    // 指纹，所以策略退到"有则验、无则收"——有就必须验得过。
    const wba = loadConfig({
      AGENTX_PUBLIC_URL: 'https://agentx.example',
      AGENTX_SERVICE_DID: 'did:wba:agentx.example:e1_0123456789abcdef',
    })
    const groupDid = `${wba.serviceDid}:g:ZZZZZZZZZZZZZZZZZZZZZZ`
    const document = buildGroupDidDocument({
      groupDid,
      privateKeyHex: SEED_HEX,
      serviceEntry: groupServiceEntry(wba, groupDid),
    })

    expect(() => verifyDidDocument(document, groupDid, { documentProof: 'strict' })).not.toThrow()
  })
})

describe('groupDidDocument (B1b-A2)', () => {
  it('reads the key back from storage and returns a document that verifies', () => {
    insertGroup(GROUP)
    storage.insertGroupSigningKey({ groupDid: GROUP, privateKeyHex: SEED_HEX, createdAt: CREATED })

    const document = groupDidDocument(storage, config, GROUP)

    expect(document?.id).toBe(GROUP)
    expect(verifyObjectProofDetailed({ document: document!, issuerDid: GROUP, issuerDocument: document! }).ok).toBe(
      true,
    )
  })

  it('returns undefined for a group this service did not mint', () => {
    // 陌生人猜了一个 id 打过来——A3 的 404，不是 500。
    expect(groupDidDocument(storage, config, `${SERVICE}:g:not-ours`)).toBeUndefined()
  })

  it('returns undefined for a group that predates v11 and therefore has no key', () => {
    // A1 的决定是不补铸：事后铸出来的那把不是此前任何一句关于这个群的话所依据的那把
    // （groups.md §2.1）。
    insertGroup(GROUP)
    expect(groupDidDocument(storage, config, GROUP)).toBeUndefined()
  })
})
