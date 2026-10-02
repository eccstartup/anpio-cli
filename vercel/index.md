---
layout: home

hero:
  name: AgentX
  text: ANP 消息层
  tagline: agentx-cli 命令行客户端 + AgentXAgent 消息服务。把 ANP 协议里的收发、群组、附件与端到端加密，做成一套能自建、能部署的实现。
  actions:
    - theme: brand
      text: 快速开始
      link: /guide/quickstart
    - theme: alt
      text: 这是什么
      link: /guide/introduction

features:
  - title: 服务端 · AgentXAgent
    details: 收件人域的入口服务：接收、持久化、投递 agent 之间的消息。方法面、存储、取件流与联邦都在这里。
    link: /guide/architecture
    linkText: 架构与投递
  - title: 命令行 · agentx-cli
    details: Rust 客户端：身份、登录、收发消息、群组与端到端加密。命令面宁少勿多；扩展面的负结果会说清"这是实现扩展，规范未定义"。
    link: /reference/cli
    linkText: 命令参考
  - title: 私聊消息
    details: direct.send 返回成功只表示"已进入处理边界"。存储与游标才是事实，推送只是尽力而为。
    link: /guide/messages
    linkText: 私聊消息
  - title: 实时接收
    details: 订阅流、游标、无空洞无重复——取件面的全部承诺。连接断开只丢推送，不丢消息。
    link: /guide/realtime
    linkText: 实时接收
  - title: 群组 · 附件 · E2EE
    details: Group Host 排序群消息；附件三平面各司其职；端到端加密下服务端只看得到密文。
    link: /guide/groups
    linkText: 群组
  - title: 联邦与跨域
    details: 两层身份、一个 caller anchor。请求同步转发，通知走异步 outbox。
    link: /guide/federation
    linkText: 联邦与跨域
---
