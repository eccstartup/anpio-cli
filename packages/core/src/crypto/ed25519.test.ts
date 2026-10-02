// `ed25519PublicKey` —— 从一把已有的私钥推公钥（B1b-A2）。
//
// 这条路径与 SDK 自己的建号流程不同：那边是"铸一把新的"，公钥直接由建号函数一并交出来。
// 这里要的是"把一把**已经存在**的钥读回来，算出它的公钥"——本服务的群钥就属于这种，它躺
// 在数据库的一列里，重启之后只剩这 32 个字节。

import { describe, expect, it } from 'vitest'
import { ed25519PublicKey } from './ed25519'

/** RFC 8032 §7.1 TEST 1 的密钥对。用规范里的已知向量而不是"自己签自己验"：后者在
 *  `getPublicKey` 与 `sign` 用错了同一套编码时照样会通过。 */
const SEED = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
const PUBLIC = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'

function bytes(hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex, 'hex'))
}

describe('ed25519PublicKey', () => {
  it('derives the RFC 8032 test vector\'s public key', () => {
    expect(Buffer.from(ed25519PublicKey(bytes(SEED))).toString('hex')).toBe(PUBLIC)
  })

  it('refuses a key that is not 32 bytes', () => {
    // 读回来的钥是一个输入边界（数据库列、keystore、文件）。@noble 对错误长度抛的是它
    // 自己的话，这里给一句能直接读懂原因的。
    expect(() => ed25519PublicKey(new Uint8Array(0))).toThrow(/32-byte Ed25519 private key/)
    expect(() => ed25519PublicKey(bytes(SEED + '00'))).toThrow(/got 33/)
  })
})
