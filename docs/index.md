---
layout: home

hero:
  name: AgentX
  text: ANP 消息层
  tagline: anpio-cli 命令行 + AgentXAgent ANPMessageService。设计先行，实现逐块落地。
  actions:
    - theme: brand
      text: 从服务端开始
      link: /docs/design/message-service
    - theme: alt
      text: 仓库总览
      link: /overview

features:
  - title: 服务端 · AgentXAgent
    details: 方法面、存储、取件流与联邦。规范 I/O 是本模块唯一的对外形状。
    link: /docs/design/message-service
    linkText: message-service
  - title: 命令面 · anpio-cli
    details: Rust 客户端。薄壳判据、与服务端的分工、退出码契约——命令面本身以 `--help` 为准。
    link: /docs/design/cli
    linkText: cli
  - title: 实时接收 · msg listen
    details: 订阅流、游标、无空洞无重复——这三条是取件面的全部承诺。
    link: /docs/design/realtime
    linkText: realtime
  - title: 群组（P4）
    details: Group Host 的语义：成员 DID、策略判定与群消息的受理顺序。
    link: /docs/design/groups
    linkText: groups
  - title: 附件与对象（P7）
    details: 消息面送清单、控制面签票据、数据面搬字节——三个平面不混淆。
    link: /docs/design/attachments
    linkText: attachments
  - title: 端到端加密（P5 / P6）
    details: 服务端只做钥匙柜与邮箱；群组一侧是 Host 排序、业主算。
    link: /docs/design/e2ee-direct
    linkText: e2ee-direct
  - title: 联邦与跨域（P8）
    details: 两层身份、一个 anchor、两条路：外层服务身份与终端业务身份分开。
    link: /docs/design/federation
    linkText: federation
  - title: 协议原语 · packages/core
    details: 从 anp-sdk 裁剪出来的那一部分：DID 组合、RFC 9421、JCS、CAIP-10。
    link: /docs/design/vendored-core
    linkText: vendored-core
---

## 这个站点是什么

九份设计文档 + 台账 + 仓库 README，**从仓库里的 Markdown 直接渲染**，没有第二份副本。
所以这里的每一页都等于仓库里的那个文件，链接到的行号也就是 `git blame` 找得到的行号。

规范出处、版本与"行号以哪份 checkout 为准"写在[总览](/overview)里（当前基线是
**ANP 1.2**，已发布）。

还没做完的事记在[台账](/todo)，台账只写**还剩什么**——做完的一律划掉，不复述。
