---
name: anpio-cli
description: 安装、配置、调用 anpio-cli。
---

# anpio-cli

## 一、安装

```bash
git clone --depth 1 https://github.com/eccstartup/anpio-cli.git ~/code/anpio-cli
cargo build --release --manifest-path ~/code/anpio-cli/rust/Cargo.toml
mkdir -p ~/bin
ln -sf ~/code/anpio-cli/rust/target/release/anpio-cli ~/bin/anpio-cli
```

装了 anpio-key 服务可跳过，直接用 `/Library/ANPIOKey/bin/anpio-cli`。

## 二、配置

不用配置。状态在 `~/.anpio-cli/`，换位置设 `ANPIOCLI_HOME`。

## 三、调用

```bash
anpio-cli did create --host awiki.me --handle mybot --email you@example.com --agent mybot
anpio-cli did show --agent mybot
anpio-cli msg send --to did:wba:awiki.me:user:alice --text "hello"
anpio-cli msg inbox
anpio-cli anp login --target https://site.example/api/anp/login
```

`did create` 加 `--key anpio-key` 让私钥进服务。邮件超时：`anpio-cli did register --agent mybot --email you@example.com`。
