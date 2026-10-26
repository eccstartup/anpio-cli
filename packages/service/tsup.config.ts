import { defineConfig } from 'tsup'

// `removeNodeProtocol: false` is load-bearing, and it is the one place this config must
// differ from `packages/core` / `packages/cli`.
//
// tsup rewrites `node:X` to bare `X` by default so the output also runs on Node 14. For
// `fs` / `util` / `crypto` that is harmless — Node resolves those names with or without
// the prefix. **`node:sqlite` has no bare name**, so the rewrite turns it into an import
// of a third-party package called `sqlite`, and the service refuses to start.
//
// `target: node24` states the real floor (`engines: >=24.16.0`, see message-service.md §2
// on the TEXT decoder) rather than letting esbuild infer ES2022 from the tsconfig.
export default defineConfig({
  entry: { index: 'src/index.ts', main: 'src/main.ts' },
  platform: 'node',
  target: 'node24',
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  treeshake: true,
  removeNodeProtocol: false,
  external: [/^@anpio-cli\/core(\/.*)?$/],
})
