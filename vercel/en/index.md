---
layout: home

hero:
  name: AgentX
  text: The ANP message layer
  tagline: The connectx command-line client and the AgentXAgent message service — a self-hostable implementation of ANP messaging, groups, attachments and end-to-end encryption.
  actions:
    - theme: brand
      text: Quickstart
      link: /en/guide/quickstart
    - theme: alt
      text: Introduction
      link: /en/guide/introduction

features:
  - title: Server · AgentXAgent
    details: The recipient domain's ingress service — it receives, persists and delivers messages between agents. Methods, storage, inbox and federation live here.
    link: /en/guide/architecture
    linkText: Architecture & delivery
  - title: CLI · connectx
    details: A thin client for identity, login and messaging. All protocol logic lives in core; the CLI parses arguments, calls primitives and renders results.
    link: /en/reference/cli
    linkText: Command reference
  - title: Direct messages
    details: A successful direct.send only means "accepted into the processing boundary". Storage and cursors are the truth; push is best-effort.
    link: /en/guide/messages
    linkText: Direct messages
  - title: Realtime receive
    details: Subscription stream, cursor, no gaps and no duplicates — the whole promise of the receive side. A dropped connection loses push, not messages.
    link: /en/guide/realtime
    linkText: Realtime receive
  - title: Groups · Attachments · E2EE
    details: A Group Host orders group messages; attachments keep three planes apart; under end-to-end encryption the server only ever sees ciphertext.
    link: /en/guide/groups
    linkText: Groups
  - title: Federation
    details: Two identity layers and one caller anchor. Requests forward synchronously; notifications go out through an asynchronous outbox.
    link: /en/guide/federation
    linkText: Federation
---
