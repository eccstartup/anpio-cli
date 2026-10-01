// C8 —— 服务自我描述（message-service.md §13）。
//
// DID 文档里那条 `ANPMessageService` 是发现链的落点，而本服务**不写 DID 文档**：它交出
// 这段 JSON，由 DID Service 在签发文档时嵌进去。这就是与 `awiki-open-server` 的接口——
// 消息服务这边的半边就到这里为止。
//
// 清单不在这里手写，来自 `capabilities.ts`，与 `anp.get_capabilities` 的运行时答复同源。
// 于是 §8.3 L591–593 那条"冲突时以运行为准"永远无事可做：静态 hint 不会与运行时不同。

import { serviceCapabilities } from './capabilities'
import type { Config } from './config'
import { RPC_PATH } from './http/server'

/** P2 §7.1 L337–347：`id` / `type` / `serviceEndpoint` 是 MUST，其余三项（`profiles` /
 *  `securityProfiles` / `serviceDid`）是 v1 的标准 hint。`x_agentx` 是本服务的扩展块，
 *  不是标准字段——标准字段里放扩展就是撒谎（§13 L834–838）。 */
export interface ServiceEntry {
  id: string
  type: 'ANPMessageService'
  serviceEndpoint: string
  serviceDid: string
  profiles: string[]
  securityProfiles: string[]
  x_agentx: { profiles: string[]; methods: string[] }
}

export function buildServiceEntry(config: Config): ServiceEntry {
  const capabilities = serviceCapabilities()
  return {
    // L339 要求 `id`。DID 文档里服务条目的 `id` 是一个 DID URL，所以这里给
    // `<serviceDid>#anp-message-service`。
    //
    // **嵌入方要把 DID 换成文档所有者的 DID**：服务条目住在被描述的那个 agent（或群）的
    // 文档里，而本服务不知道对方是谁，也就给不出那个 id。这里给不出比给错好——本服务的
    // DID 至少是一个真实存在、可解析的 DID，不是一个占位符。
    id: `${config.serviceDid}#anp-message-service`,
    type: 'ANPMessageService',
    serviceEndpoint: `${config.publicUrl}${RPC_PATH}`,
    serviceDid: config.serviceDid,
    profiles: capabilities.profiles,
    securityProfiles: capabilities.securityProfiles,
    x_agentx: {
      profiles: capabilities.extensionProfiles,
      // 方法按 Profile 归属读：`stream.*` 那两个的传输是 WebSocket 而不是这个 rpc 端点
      // （realtime.md §9），块里列出它们是在说"这个服务有这些扩展方法"，不是在说它们都
      // 能 POST 到这里。传输由 Profile 决定，所以不另开一个按传输分组的形状。
      methods: capabilities.extensionMethods,
    },
  }
}
