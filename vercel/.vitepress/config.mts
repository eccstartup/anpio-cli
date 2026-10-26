// AgentX docs — a self-contained, bilingual VitePress site.
//
// This directory is the deployment root: point a Vercel project at `vercel/` and it
// runs `npm install` + `npm run docs:build`, publishing `.vitepress/dist`. Nothing here
// reads the rest of the monorepo, so the docs build cannot be broken by a source change.
//
// Two locales, one source each: Chinese at `/`, English under `/en/`. Every guide page
// carries at least one Mermaid diagram (architecture, flow or sequence), so the
// Mermaid plugin is part of the config rather than an optional flourish.

import { defineConfig } from 'vitepress'
import { withMermaid } from 'vitepress-plugin-mermaid'

const REPO = 'https://github.com/eccstartup/AgentX'
const DESCRIPTION =
  'ANP message layer: the anpio-cli command-line client and the AgentXAgent message service.'

const zhTheme = {
  nav: [
    { text: '指南', link: '/guide/introduction' },
    { text: '参考', link: '/reference/rpc' },
    { text: 'GitHub', link: REPO },
  ],
  sidebar: [
    {
      text: '开始',
      items: [
        { text: '介绍', link: '/guide/introduction' },
        { text: '快速开始', link: '/guide/quickstart' },
      ],
    },
    {
      text: '指南',
      collapsed: false,
      items: [
        { text: '架构与投递', link: '/guide/architecture' },
        { text: '身份与定址', link: '/guide/identity' },
        { text: '私聊消息', link: '/guide/messages' },
        { text: '实时接收', link: '/guide/realtime' },
        { text: '群组', link: '/guide/groups' },
        { text: '附件', link: '/guide/attachments' },
        { text: '端到端加密', link: '/guide/e2ee' },
        { text: '联邦与跨域', link: '/guide/federation' },
        { text: '部署与配置', link: '/guide/deploy' },
      ],
    },
    {
      text: '参考',
      items: [
        { text: 'anpio-cli 命令', link: '/reference/cli' },
        { text: 'RPC 方法', link: '/reference/rpc' },
        { text: '订阅流协议', link: '/reference/stream' },
        { text: '错误码', link: '/reference/errors' },
        { text: 'HTTP 端点与自述', link: '/reference/endpoints' },
      ],
    },
  ],
  outline: { level: [2, 3], label: '本页' },
  docFooter: { prev: '上一篇', next: '下一篇' },
  lastUpdated: { text: '最后更新' },
  returnToTopLabel: '回到顶部',
  sidebarMenuLabel: '目录',
  darkModeSwitchLabel: '主题',
  lightModeSwitchTitle: '切换到浅色模式',
  darkModeSwitchTitle: '切换到深色模式',
  editLink: { pattern: `${REPO}/edit/main/vercel/:path`, text: '在 GitHub 上修改这一页' },
  footer: {
    message: 'ANP 消息层：anpio-cli 命令行 + AgentXAgent 消息服务',
    copyright: 'MIT License',
  },
}

const enTheme = {
  nav: [
    { text: 'Guide', link: '/en/guide/introduction' },
    { text: 'Reference', link: '/en/reference/rpc' },
    { text: 'GitHub', link: REPO },
  ],
  sidebar: [
    {
      text: 'Get started',
      items: [
        { text: 'Introduction', link: '/en/guide/introduction' },
        { text: 'Quickstart', link: '/en/guide/quickstart' },
      ],
    },
    {
      text: 'Guides',
      collapsed: false,
      items: [
        { text: 'Architecture & delivery', link: '/en/guide/architecture' },
        { text: 'Identity & addressing', link: '/en/guide/identity' },
        { text: 'Direct messages', link: '/en/guide/messages' },
        { text: 'Realtime receive', link: '/en/guide/realtime' },
        { text: 'Groups', link: '/en/guide/groups' },
        { text: 'Attachments', link: '/en/guide/attachments' },
        { text: 'End-to-end encryption', link: '/en/guide/e2ee' },
        { text: 'Federation', link: '/en/guide/federation' },
        { text: 'Deploy & configure', link: '/en/guide/deploy' },
      ],
    },
    {
      text: 'Reference',
      items: [
        { text: 'anpio-cli commands', link: '/en/reference/cli' },
        { text: 'RPC methods', link: '/en/reference/rpc' },
        { text: 'Stream protocol', link: '/en/reference/stream' },
        { text: 'Error codes', link: '/en/reference/errors' },
        { text: 'HTTP endpoints', link: '/en/reference/endpoints' },
      ],
    },
  ],
  outline: { level: [2, 3], label: 'On this page' },
  docFooter: { prev: 'Previous', next: 'Next' },
  lastUpdated: { text: 'Last updated' },
  returnToTopLabel: 'Return to top',
  sidebarMenuLabel: 'Menu',
  darkModeSwitchLabel: 'Appearance',
  lightModeSwitchTitle: 'Switch to light theme',
  darkModeSwitchTitle: 'Switch to dark theme',
  editLink: { pattern: `${REPO}/edit/main/vercel/:path`, text: 'Edit this page on GitHub' },
  footer: {
    message: 'ANP message layer: the anpio-cli CLI and the AgentXAgent message service',
    copyright: 'MIT License',
  },
}

// The local-search box falls back to hard-coded English strings, so the Chinese UI needs an
// explicit translation set keyed by locale (`root` is the zh-CN locale's index). English is
// left out on purpose: the built-in defaults already are English.
const search = {
  provider: 'local' as const,
  options: {
    locales: {
      root: {
        translations: {
          button: { buttonText: '搜索', buttonAriaLabel: '搜索' },
          modal: {
            displayDetails: '显示详细列表',
            resetButtonTitle: '重置搜索',
            backButtonTitle: '关闭搜索',
            noResultsText: '没有找到',
            footer: {
              selectText: '选择',
              selectKeyAriaLabel: '回车',
              navigateText: '切换',
              navigateUpKeyAriaLabel: '上箭头',
              navigateDownKeyAriaLabel: '下箭头',
              closeText: '关闭',
              closeKeyAriaLabel: 'Esc',
            },
          },
        },
      },
    },
  },
}

export default withMermaid(
  defineConfig({
    title: 'AgentX',
    description: DESCRIPTION,
    cleanUrls: true,
    // Every page uses `<did>`, `<group_did>` and `<object_id>` as placeholders. With HTML
    // parsing on, `<dir>`-shaped ones become tags while `<upload_uri>` stays literal; off,
    // all of them are escaped the same way. No page here uses raw HTML.
    markdown: { html: false },
    // `fastdom` ships CommonJS while mermaid imports it as ESM. Vite's dep optimizer has to
    // pre-bundle it or the dev server dies with "does not provide an export named 'default'"
    // (the production build is unaffected — it goes through Rollup's interop).
    vite: {
      server: { host: '127.0.0.1', port: 5173 },
      optimizeDeps: { include: ['mermaid', 'fastdom'] },
    },
    mermaid: { theme: 'neutral' },
    mermaidPlugin: { class: 'mermaid' },
    // Local search has to sit on the *root* themeConfig: VitePress decides whether to ship
    // the search bundle from `site.themeConfig.search.provider`, which reads the root only.
    // Each locale's themeConfig is merged over this one, so nav/sidebar/footer stay per-language.
    themeConfig: { search },
    locales: {
      root: {
        label: '简体中文',
        lang: 'zh-CN',
        themeConfig: zhTheme,
      },
      en: {
        label: 'English',
        lang: 'en',
        link: '/en/',
        themeConfig: enTheme,
      },
    },
  }),
)
