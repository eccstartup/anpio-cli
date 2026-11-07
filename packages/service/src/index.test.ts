import { describe, expect, it } from 'vitest'
import {
  createEgress,
  createRelay,
  loadHttpSigner,
  type Egress,
  type EgressAnswer,
  type ForwardOutcome,
  type HttpSigner,
  type OutboundRequest,
  type Relay,
} from './index'

// 这一条咬的是**库入口**：嵌入方拿得到 `createDispatch`，就必须也能合法地造出它要的
// relay——否则只能在自己仓库里复制一份转发/出站逻辑。转发本身的行为归
// `federation/crossDomain.test.ts` 与 `federation/forward.test.ts` 管；这里一个服务也不
// 起，一个网络请求也不发。

describe('the library entry can build a relay', () => {
  it('exports the three constructors', () => {
    expect(typeof createRelay).toBe('function')
    expect(typeof createEgress).toBe('function')
    expect(typeof loadHttpSigner).toBe('function')
  })

  it('exports the types an embedder needs to wire them together', () => {
    // 类型赋值只是编译期检查，运行期这一段什么也不做。它防的是"构造函数导出着、类型却
    // 被后续重构漏掉"——那样嵌入方的 `tsc` 会先于任何测试报错。
    const egress: Egress = {
      async post(): Promise<EgressAnswer> {
        return { status: 200, headers: {}, body: undefined }
      },
    }

    const relay: Relay = {
      async forward(): Promise<ForwardOutcome> {
        return { kind: 'local' }
      },
    }

    const signer: HttpSigner = {
      keyid: 'did:wba:example.com:service:anp:e1_svc#key-1',
      async headers(request: OutboundRequest): Promise<Record<string, string>> {
        void request
        return {}
      },
    }

    expect(relay).toBeDefined()
    expect(egress).toBeDefined()
    expect(signer).toBeDefined()
  })
})
