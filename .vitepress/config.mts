// VitePress 配置。
//
// **一个来源，两份呈现**：`srcDir` 指向仓库根，也就是 `README.md`、`TODO1.md` 与
// `docs/design/*.md` 原样成为站点页面——没有第二份拷贝，所以不会出现"站点说的和仓库说的
// 不一样"。`rewrites` 只改 URL，不改文件（`README.md` 直接当首页会与 `docs/index.md`
// 抢 `/`）。
//
// 站点的**唯一**用途是读设计文档，所以不做博客、不做搜索索引以外的东西。刻意**不**装
// 本地搜索（`@vueuse/core` 那一套）以外的插件，也不加 i18n：文档本来就只有中文一份。

import { defineConfig } from 'vitepress'

const REPO = 'https://github.com/eccstartup/AgentX'

export default defineConfig({
  lang: 'zh-CN',
  title: 'AgentX',
  description: 'ANP 消息层：connectx CLI + AgentXAgent ANPMessageService',
  srcDir: '.',
  // 默认只忽略 `**/node_modules/**` 与 `**/dist/**`。这个 srcDir 是仓库根，所以工作区
  // 里的源码与测试也会被扫到；`audit_reports/` 是本地历史报告的落点（已 gitignore），
  // 它们**只读**，不该出现在站点上。`.vitepress/` 与 `.claude/` 是点目录，glob 默认不
  // 匹配，不必再列。
  srcExclude: ['packages/**', 'audit_reports/**'],
  rewrites: {
    'docs/index.md': 'index.md',
    'README.md': 'overview.md',
    'TODO1.md': 'todo.md',
  },
  cleanUrls: true,
  // 文档里到处是 `<upload_uri>`、`<digest>`、`<dir>` 这种**占位符**。开着 HTML 解析时
  // `<dir>` 会被当成标签交给 Vue 编译，`<upload_uri>` 又因为下划线不构成标签而留成字面
  // 量——同一份文档里两种行为。关掉 HTML 解析，全部按字面量转义，行为一致；本仓库的
  // markdown 也确实一处原生 HTML 都没用。
  markdown: { html: false },
  themeConfig: {
    nav: [
      { text: '总览', link: '/overview' },
      { text: '设计', link: '/docs/design/message-service' },
      { text: '台账', link: '/todo' },
      { text: 'GitHub', link: REPO },
    ],
    sidebar: [
      {
        text: '开始',
        items: [
          { text: '总览', link: '/overview' },
          { text: '台账（还剩什么）', link: '/todo' },
        ],
      },
      {
        text: '设计',
        items: [
          { text: 'AgentXAgent —— 服务端', link: '/docs/design/message-service' },
          { text: 'connectx —— 命令面', link: '/docs/design/cli' },
          { text: '实时接收 · msg listen', link: '/docs/design/realtime' },
          { text: 'packages/core —— 协议原语', link: '/docs/design/vendored-core' },
        ],
      },
      {
        text: '协议 Profile',
        items: [
          { text: '群组（P4）', link: '/docs/design/groups' },
          { text: '附件与对象（P7）', link: '/docs/design/attachments' },
          { text: '私聊端到端加密（P5）', link: '/docs/design/e2ee-direct' },
          { text: '群组端到端加密（P6）', link: '/docs/design/e2ee-group' },
          { text: '联邦与跨域（P8）', link: '/docs/design/federation' },
        ],
      },
    ],
    outline: { level: [2, 3], label: '本页' },
    docFooter: { prev: '上一篇', next: '下一篇' },
    lastUpdated: { text: '最后更新' },
    returnToTopLabel: '回到顶部',
    sidebarMenuLabel: '目录',
    darkModeSwitchLabel: '主题',
    editLink: {
      pattern: `${REPO}/edit/main/:path`,
      text: '在 GitHub 上修改这一页',
    },
    footer: {
      message: 'ANP 消息层：connectx CLI + AgentXAgent ANPMessageService',
      copyright: 'MIT License',
    },
  },
})
