import { defineConfig } from 'tsup'

// connectx 是 Node-only，以 bin 形式发布。只出 ESM：shebang（`#!/usr/bin/env node`）
// 要能被 `node dist/cli.js` 直接跑。`@agentx/core`（含 `./advanced` 子路径）与
// `picocolors` 保持 external（运行时依赖），从使用方的 node_modules 解析——不打进包。
//
// `@clack/prompts` 与 `jiti` 已随 `project` 族一起删除（TODO1 B2）：CLI 不再生成
// 脚手架，也就不再需要交互式提示与运行时 TS 加载。
export default defineConfig({
  entry: { cli: 'src/cli.ts' },
  format: ['esm'],
  dts: false,
  sourcemap: true,
  clean: true,
  treeshake: true,
  external: [/^@agentx\/core(\/.*)?$/, 'picocolors'],
})
