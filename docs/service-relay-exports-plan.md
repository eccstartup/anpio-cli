# service 包 relay 公开入口计划

2026-11-02。状态：待实现。

使用方：anpio-agents 的跨域投递接入（该仓库的 `docs/anp-cross-domain-plan.md`）。
它们只调用本包的公开入口，不在自己仓库里复制 relay / egress / DID 发现。

## 背景

跨域转发已经实现，并且二进制路径已经接上：

- `packages/service/src/main.ts` 用
  `relay: createRelay({ config, egress })` 把 relay 注入 `createDispatch`；
- `rpc/dispatch.ts` 的 `RELAYED_METHODS` 包含 `direct.send`；
- `federation/crossDomain.test.ts` 覆盖跨域投递。

缺口只在**库入口**：

- `packages/service/src/index.ts` 只导出了 `createDispatch` 和 `DispatchDeps`；
  `Relay` 类型因为出现在 `DispatchDeps` 里被带进 `dist/index.d.ts`，但构造它的
  `createRelay` / `createEgress` / `loadHttpSigner` 都没有导出。
- `packages/service/package.json` 的 `exports` 只开 `"."`，所以嵌入方也不能通过
  `@anpio-cli/service/dist/federation/forward.js` 这样的深路径绕过。

结果：嵌入方（anpio-agents）能拿到 `createDispatch`，却无法合法地造出一个 relay 传进去，
只能复制一份转发/出站逻辑——这正是 `index.ts` 文件头说的“公开契约显式列出”要避免的事。

## 目标

公开入口可以完整构造并注入 relay，二进制的行为一行不变：

```ts
import {
  createDispatch,
  createEgress,
  createRelay,
  loadHttpSigner,
} from '@anpio-cli/service'
```

## 改动

### 1. `packages/service/src/index.ts`

在现有 `createDispatch` / `DispatchDeps` 导出旁边加：

```ts
export { createRelay } from './federation/forward'
export type { Relay, RelayOptions, ForwardOutcome } from './federation/forward'

export { createEgress } from './federation/egress'
export type { Egress, EgressOptions, EgressAnswer } from './federation/egress'

export { loadHttpSigner } from './federation/signing'
export type { HttpSigner, OutboundRequest } from './federation/signing'
```

不要导出整个 `federation/`，保持“每个名字显式列出”的现有约定。

### 2. 回归测试

新增 `packages/service/src/index.test.ts`（vitest 的 `include` 已覆盖
`src/**/*.test.ts`）：

- 从 `./index` 导入 `createRelay` / `createEgress` / `loadHttpSigner`，断言都是函数；
- 从 `./index` 导入类型 `Relay` / `Egress` / `HttpSigner`，用一个最小的 relay 替身做类型
  赋值，防止类型导出被后续重构漏掉；
- 不启动服务、不发网络请求。

这个测试咬的是“公开入口还能不能构造 relay”，不是转发逻辑；转发逻辑继续由
`federation/crossDomain.test.ts` 负责。

### 3. 重建 dist

```bash
npm run build:service
```

`packages/service` 是 `file:` 依赖，anpio-agents 直接用 `dist/index.js` 与
`dist/index.d.ts`。类型与运行时都要确认：

```bash
node --input-type=module -e "import('@anpio-cli/service').then(m => console.log(typeof m.createRelay, typeof m.createEgress, typeof m.loadHttpSigner))"
```

（在 anpio-agents 仓库里执行；应输出 `function function function`。）

### 4. 文档

在 `docs/design/federation.md` §3.3 末尾补一段：

- 嵌入方通过 `createDispatch({ relay: createRelay({ config, egress }) })` 接入跨域；
- **服务无法知道哪些 agent DID 在本机**，因此“本机目标不做出站解析”的短路由嵌入方
  用 `Relay` 包装完成（命中本机 DID 直接返回 `{ kind: 'local' }`）。这一条要写进文档，
  否则下一个嵌入方会以为 relay 自己认得本机目标，结果本机消息依赖 DID 文档可达。
- `main.ts` 与嵌入方走同一个 `createRelay`，不另开一条实现。

## 验收

- `npm run typecheck:service`
- `npm run test:service`
- `npm run build:service`
- 在 anpio-agents 中：`npm run check` 能通过
  `import { createRelay, createEgress, loadHttpSigner } from '@anpio-cli/service'`，
  且上面的运行时导出检查输出三个 `function`。

## 不做

- 不改 `forward.ts` / `egress.ts` / `dispatch.ts` 的任何逻辑。
- 不让 `createDispatch` 自动创建 relay；仍由调用方显式注入，保持“是否部署跨域”是可配置
  的决定。
- 不开 `exports` 子路径；公开面仍只有包根。
- 不改 `loadHttpSigner` 的配置来源；缺少 `ANPIOCLI_KEY_FILE` 时仍返回 `undefined`
  （不签外层身份是合法部署）。
- 不导出 `createHttpSigner`；嵌入方如果需要自己的钥，后续再单独讨论。

## 风险

- 纯增量导出，不改行为；ESM 与 CJS 两份产物都会带这三个函数。
- `treeshake: true` 不会裁掉被 `index.ts` 显式导出的符号。
- 如果未来把 `Relay` 拆成多个子接口，这次导出的类型名会成为公开契约，改名需要按库的
  兼容策略处理。
