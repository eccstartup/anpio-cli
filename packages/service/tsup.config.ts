import { defineConfig } from 'tsup'

export default defineConfig({
  entry: { index: 'src/index.ts', main: 'src/main.ts' },
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  treeshake: true,
  external: [/^@agentx\/core(\/.*)?$/],
})
