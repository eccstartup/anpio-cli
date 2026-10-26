---
title: HTTP 端点
description: 全部路由与状态码、两段自我描述 JSON，以及 anp.get_capabilities 的返回字段。
---

# HTTP 端点

一个 AnpioAgent 进程只暴露这几条路由。控制面与数据面是两套错误约定：**控制面一律 200 +
信封里的错误**，**数据面用真实状态码**（它没有 JSON-RPC 信封，也没有 `id` 可答）。

## 路由

| 路由 | 方法 | 说明 |
|---|---|---|
| `/anp-im/rpc` | `POST` | 控制面。`Content-Type` 必须是 `application/json` |
| `/anp-im/stream` | `GET` + WebSocket 升级 | 订阅流。普通 GET 回 `426` |
| `/anp-im/upload/{token}` | `PUT` | 数据面：传对象字节，`{token}` 本身就是凭据 |
| `/anp-im/objects/{object_id}` | `GET` | 数据面：取对象字节，凭据在 `Authorization` 头 |
| `/.well-known/anp-message-service.json` | `GET` | 服务自述（下节） |

其余路径一律 `404`。

## 状态码

### 控制面 `/anp-im/rpc`

| 码 | 何时 |
|---|---|
| `200` | 正常。**业务错误也在 200 里**，看 `error.data.anp_code` |
| `401` | **外层** HTTP 认证失败。带 `WWW-Authenticate: DIDWba realm=…, error=…`，正文镜像同一组字段，**没有 `id`**——这一步跑在 JSON-RPC 之前 |
| `503` | 外层认证 **`unverifiable`**（我们自己得不出结论）。**不**进挑战头：回 401 会把对端送去重签一份没问题的请求 |
| `405` / `415` / `413` | 方法不对 / 不是 JSON / 请求体超过 `ANPIOCLI_MAX_BODY` |

### 订阅 `/anp-im/stream`

| 码 | 何时 |
|---|---|
| `426` | 普通 GET（缺升级）。说方法错会冤枉唯一对的那部分 |
| `405` | 非 GET |

协议层的错误（帧里的错误信封、关闭码）见 [实时订阅](/reference/stream)。

### 数据面

| 码 | 何时 |
|---|---|
| `200` | 上传收下 / 对象发出 |
| `400` | 资源段拼不出来 |
| `401` | 缺 `Bearer` 票据，或票据不认识 / 已作废（`downloadTicketInvalid`） |
| `403` | 票据不绑这个对象（`ticketBindingMismatch`） |
| `404` | 未知上传令牌、槽位已废弃 / 已不在 `pending`、没有已提交的对象（`objectUnavailable`） |
| `410` | 槽位或票据已过期 |
| `413` | 对象超过 `ANPIOCLI_MAX_OBJECT_BYTES`（`objectTooLarge`） |
| `501` / `405` | 该路由没接 / 方法不对 |

数据面的拒绝体**没有信封**，所以它把 `code`、`anp_code` 都写进 JSON：

```json
{ "error": "…", "code": 6010, "anp_code": "anp.attachment.digest_mismatch" }
```

两个细节：上传**不看** `origin_proof`（它是普通 HTTP 客户端发的，全部凭据就是 URL 里
那段一次性令牌）；下载的票据**只认 `Authorization` 头**，`?ticket=` 之类连读都不读。
下载响应的 `Content-Type` 固定 `application/octet-stream`，并带
`Content-Disposition: attachment` 与 `X-Content-Type-Options: nosniff`——不按对端声明的
MIME 回，否则一个 `text/html` 对象就是我们域名下的一个页面。

## 服务自述 `/.well-known/anp-message-service.json`

**本服务不写 DID 文档**：它交出这段 JSON，由 DID Service 在签发文档时嵌进去。

```json
{
  "id": "<serviceDid>#anp-message-service",
  "type": "ANPMessageService",
  "serviceEndpoint": "<publicUrl>/anp-im/rpc",
  "serviceDid": "…",
  "profiles": ["anp.core.binding.v1", "…"],
  "securityProfiles": ["transport-protected", "group-e2ee"],
  "x_anpiocli": { "profiles": ["x_anpiocli.inbox.v1", "x_anpiocli.stream.v1"], "methods": ["…"] }
}
```

- 前六项是标准字段，`id` / `type` / `serviceEndpoint` 是 MUST，其余是 v1 的标准 hint。
- **嵌入方要把 `id` 换成文档所有者的 DID**——服务条目住在被描述的那个 agent（或群）的
  文档里，而本服务不知道对方是谁，给不出那个 id。这里给的是它自己的 DID，那是真实可解析
  的，不是占位符。
- `x_anpiocli` 是扩展块。**标准字段里不放扩展**，那等于让一个只实现规范的服务看起来支持它。
- `profiles` / `securityProfiles` 来自 `capabilities.ts`，与下面运行时答复**同源**，所以
  不会出现"文档说的和运行的不一样"。

## `anp.get_capabilities` 的返回

```json
{
  "service_did": "…",
  "supported_profiles": ["…"],
  "supported_security_profiles": ["…"],
  "limits": { "max_request_bytes": "1048576", "max_message_bytes": "1048576" },
  "supported_content_types": ["…"]
}
```

- 只放**规范**定义的字段。扩展能力（`x_anpiocli.*`）**不**出现在这里——这个结果是"规范能力"
  的运行时权威，掺扩展会让标准客户端推出错误结论。扩展的自我描述在 `.well-known` 的
  `x_anpiocli` 块与 `stream.hello` 的 `profiles` 两处。
- `limits` 的值是**十进制字符串**，不是数字。
- `max_message_bytes` 报的是请求体上限：消息装在请求里走，不可能比请求上限更大。
- **`anp.group.e2ee.v2`（P6）被扣留**：方法照做、直接发能受理，但不会声明成稳定 Profile，
  因为它的 MLS `ExtensionType` code point 还没注册。

## 下一步

- [错误码](/reference/errors) —— 信封里的码。
- [附件](/guide/attachments) —— 数据面两条路由的完整流程。
- [部署与配置](/guide/deploy) —— `publicUrl` 与各上限从哪来。
