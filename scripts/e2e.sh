#!/usr/bin/env bash
#
# e2e：一条命令跑完 Rust 客户端的一条链路（TODO6 §5.3 第二档）。
#
# 这就是把 §6 那份手工配方钉成脚本——手工步骤是最先过时的那一类东西，所以它得能复跑。
# 链路是**真进程**跑出来的：真的起一台 DID 主机、真的起本仓的 `packages/service`、
# 真的用 `agentx-cli` 二进制发请求；替掉的只有"DID 文档谁托管"这一件事，替法见
# 【DID 主机】那段。
#
#   ./scripts/e2e.sh                  # 建好再跑
#   ./scripts/e2e.sh --no-build       # 用现成的产物
#   ./scripts/e2e.sh --with-awiki     # 多跑一遍"对真 awiki 主机"，需要它已经在 8765 上
#
# 退出码非 0 就是有断言没过；每一步都会把命令与观察到的输出打出来，失败时不用猜，
# 并且失败时会把服务与主机两份日志的尾部一并打出来。
#
# ---------------------------------------------------------------------------
# 【需要 awiki 吗】
#
# **默认不需要。** 本脚本自带一台玩具 DID 主机（`scripts/e2e/did_host.py`），
# 于是整条链路一条命令、一个仓库就能跑——CI 里不需要第二个 checkout。
#
# awiki 的角色被收窄到它**唯一能演**的那半截：`did create` / `did publish` / `me`
# 对**真主机**跑一遍，看它收不收我们造的文档（TODO6 §5.2 裁定甲的原话是"用这个跑"）。
# 这一遍用 `--with-awiki` 打开，前置条件明写在这里：
#
#   cd ~/code/claude/awiki-open-server
#   PYTHONPATH=src AWIKI_DATA_DIR=/tmp/awiki-data \
#     AWIKI_PUBLIC_BASE_URL=http://127.0.0.1:8765 AWIKI_DID_DOMAIN=localhost \
#     uv run uvicorn 'awiki_open_server.app.main:create_app' \
#     --factory --host 127.0.0.1 --port 8765
#
# 不开这个开关时，脚本不会假装那半截跑过。
#
# **这一遍会在那台 awiki 上留下一条身份**：`register` 没有对应的删除，而且 handle 是
# 唯一的、重复注册会被拒（`handle_already_registered`）。所以 handle 每次带时间戳，
# 脚本也因此**可以**重复跑——代价是那个 checkout 会慢慢攒下一批 `e2e-awiki-*`。
# 这正是它默认不开的原因。
#
# ---------------------------------------------------------------------------
# 【DID 主机为什么是玩具的】
#
# `msg` / `group` / `group e2ee` 要打的是**本仓的** `packages/service`，而身份文档里的
# `serviceEndpoint` / `serviceDid` 是由**主机**说了算的（`identity/host.rs::fetch_host_service`
# 从主机自己的 `/.well-known/did.json` 里读）。awiki 只肯发端点指向它自己的文档，所以拿它
# 当主机就**测不到**"对端服务在别处"。`packages/e2e/src/harness.ts` 起玩具主机的理由与此
# 逐字相同——这不是本脚本发明的东西，是本仓既有的那个决定。
#
# 于是这台主机只演一句话：它对外宣告的身份就是本仓服务的身份
# （`AGENTX_SERVICE_DID` 设成同一个值），awiki 那套"主机即消息服务"的关系照旧成立，
# 只是消息服务换成了我们的。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD=1
WITH_AWIKI=0
AWIKI_DIR="${AWIKI_DIR:-$HOME/code/claude/awiki-open-server}"
AWIKI_URL="${AWIKI_URL:-http://127.0.0.1:8765}"

while [ $# -gt 0 ]; do
  case "$1" in
    --no-build) BUILD=0 ;;
    --with-awiki) WITH_AWIKI=1 ;;
    -h|--help) sed -n '2,45p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
  shift
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/agentx-e2e.XXXXXX")"
mkdir -p "$WORK/svc/objects"
HOST_PID=""
SERVICE_PID=""
FAILED=0

cleanup() {
  [ -n "$SERVICE_PID" ] && kill "$SERVICE_PID" 2>/dev/null || true
  [ -n "$HOST_PID" ] && kill "$HOST_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  # 失败时把两份日志留下来——"服务没起来"这种失败，答案永远在那里面，删掉工作目录
  # 就等于把唯一能看的东西扔了。
  if [ "$FAILED" -ne 0 ]; then
    printf '\n---- service log (last 30 lines) ----\n'
    tail -30 "$WORK/svc.log" 2>/dev/null || true
    printf '\n---- DID host log (last 30 lines) ----\n'
    tail -30 "$WORK/host.log" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# ---- 小工具 ------------------------------------------------------------------

section() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# 跑一条命令，把输出留在一个文件里；返回它真正的退出码（`set -e` 下要显式接住）。
LAST_OUT=""
LAST_STATUS=0
run() {
  LAST_OUT="$WORK/out.txt"
  set +e
  "$@" >"$LAST_OUT" 2>&1
  LAST_STATUS=$?
  set -e
  sed 's/^/    /' "$LAST_OUT"
  return 0
}

# 同上，但**不把输出打出来**：只用来取一个字段的命令（`--json` 的 `group create` 会吐一整份
# 收据，几十行，淹没真正要看的断言）。
run_quiet() {
  LAST_OUT="$WORK/out.txt"
  set +e
  "$@" >"$LAST_OUT" 2>&1
  LAST_STATUS=$?
  set -e
  return 0
}

# 断言上一条 `run` 的输出里有某个字符串。
expect() {
  local why="$1" needle="$2"
  if grep -qF -- "$needle" "$LAST_OUT"; then
    printf '    \033[32mok\033[0m   %s\n' "$why"
  else
    printf '    \033[31mFAIL\033[0m %s\n         expected to find: %s\n' "$why" "$needle"
    FAILED=$((FAILED + 1))
  fi
}

# 断言上一条 `run` 以某个退出码结束。
expect_status() {
  local why="$1" want="$2"
  if [ "$LAST_STATUS" = "$want" ]; then
    printf '    \033[32mok\033[0m   %s\n' "$why"
  else
    printf '    \033[31mFAIL\033[0m %s\n         expected exit %s, got %s\n' "$why" "$want" "$LAST_STATUS"
    FAILED=$((FAILED + 1))
  fi
}

# 从上一份输出里取一个 JSON 字段（`--json` 那一档才用）。
field() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$LAST_OUT" "$1"
}

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

# 等一个地址能连上（服务/主机的起动是异步的，端口先探测再跑第一步）。
wait_for_port() {
  local port="$1" name="$2" tries=100
  while [ "$tries" -gt 0 ]; do
    if python3 -c "import socket,sys; s=socket.socket(); s.settimeout(0.2); sys.exit(0 if s.connect_ex(('127.0.0.1',int(sys.argv[1])))==0 else 1)" "$port"; then
      return 0
    fi
    tries=$((tries - 1))
    sleep 0.1
  done
  echo "FAIL: $name never came up on 127.0.0.1:$port" >&2
  exit 1
}

# ---- 建 ----------------------------------------------------------------------

if [ "$BUILD" = 1 ]; then
  section "build"
  ( cd "$ROOT/rust" && cargo build -q )
  # core 也要建：服务按**包名**引 `@agentx/core`，而那个名字解析到 `packages/core/dist`
  # （`core/package.json` 的 `exports`）。全新 clone 上只建服务，服务就起不来，
  # 且那样子像是"服务坏了"而不是"少建了一步"（CI 的注释里记的是同一件事）。
  ( cd "$ROOT" && npm run build:core >/dev/null && npm run build:service >/dev/null )
  echo "    ok   rust binary + core + service dist"
fi

CLI="$ROOT/rust/target/debug/agentx-cli"
[ -x "$CLI" ] || { echo "FAIL: $CLI is missing — run without --no-build" >&2; exit 1; }

# ---- 起 host 与 service -------------------------------------------------------

SERVICE_PORT="$(free_port)"
HOST_PORT="$(free_port)"
AUTHORITY="localhost%3A${HOST_PORT}"
SERVICE_DID="did:wba:${AUTHORITY}"
SERVICE_ENDPOINT="http://127.0.0.1:${SERVICE_PORT}/anp-im/rpc"

section "start the DID host and the service"
echo "    host    http://localhost:${HOST_PORT}  (${SERVICE_DID})"
echo "    service http://127.0.0.1:${SERVICE_PORT}"

python3 "$ROOT/scripts/e2e/did_host.py" \
  --port "$HOST_PORT" \
  --service-did "$SERVICE_DID" \
  --service-endpoint "$SERVICE_ENDPOINT" \
  >"$WORK/host.log" 2>&1 &
HOST_PID=$!

# `AGENTX_SERVICE_DID` 与服务在主机的 `/.well-known/did.json` 里宣告的必须**逐字相同**：
# 客户端把主机宣告的那个写进身份文档，服务再拿它核 `meta.target.did`。两处不一样，
# 每一步都会以 `anp.invalid_target_binding` 被拒。
AGENTX_LISTEN="127.0.0.1:${SERVICE_PORT}" \
AGENTX_PUBLIC_URL="http://127.0.0.1:${SERVICE_PORT}" \
AGENTX_SERVICE_DID="$SERVICE_DID" \
AGENTX_DB="$WORK/svc/svc.db" \
AGENTX_OBJECT_DIR="$WORK/svc/objects" \
AGENTX_DID_DEV_HOSTS="127.0.0.1,localhost" \
  node "$ROOT/packages/service/dist/main.js" >"$WORK/svc.log" 2>&1 &
SERVICE_PID=$!

wait_for_port "$HOST_PORT" "the DID host"
wait_for_port "$SERVICE_PORT" "the service"

export AGENTXCLI_HOME="$WORK/home"
# 这台主机的权威段是 `localhost`，而服务在 `127.0.0.1` 上——两个都放行。
export AGENTX_DID_DEV_HOSTS="127.0.0.1,localhost"

# ---- 身份：did create / show / publish / me ----------------------------------

section "did create — an identity whose document names our own service"
for name in alice bob; do
  run "$CLI" did create --host "http://localhost:${HOST_PORT}" --handle "$name" --agent "$name"
  expect_status "did create $name succeeds" 0
  expect "  and says it registered with the host" "registered with"
done

section "did show — the identity as this client sees it"
run "$CLI" did show --agent alice
expect_status "did show succeeds" 0
expect "  and prints the DID it just made" "did:wba:${AUTHORITY}:user:alice:"

section "did publish — nothing changed is a no-op, an edit moves the version"
run "$CLI" did publish --agent alice
expect_status "the first publish settles" 0
expect "  and reports the version it left behind" "version: 1"

# 在_store 里改一笔，模拟"本地文档动过"。`did publish` 会重签再发；不重签的话，
# store 里就留着一份 proof 盖不住自己的文档（§6 记的正是这件事）。
python3 - "$WORK/home/alice/default/identity.json" <<'PY'
import json, sys
path = sys.argv[1]
document = json.load(open(path))
document["did_document"]["alsoKnownAs"] = ["https://e2e.invalid/alice"]
json.dump(document, open(path, "w"), indent=1)
print("edited the stored document")
PY

run "$CLI" did publish --agent alice
expect_status "the second publish goes through" 0
expect "  and moves the version 1 -> 2" "version: 1 -> 2"

run "$CLI" did publish --agent alice
expect "a third publish is a no-op again" "already serves this document"

section "me set / show — the host's own profile surface"
run "$CLI" me set --agent alice --name "Alice 爱丽丝" --bio "e2e"
expect_status "me set succeeds" 0
run "$CLI" me show --agent alice
expect_status "me show succeeds" 0
expect "  and shows the nickname" "Alice 爱丽丝"
expect "  and shows the blurb" "e2e"

section "the refusal that must happen with nothing set up"
run "$CLI" me set --agent alice
expect_status "me set with no fields exits 1" 1
expect "  and names what is missing" "nothing to set"

# `did publish` 要的是 register 交回来的 bearer token。删掉它，就是"这一步从没发生过"。
cp "$WORK/home/alice/default/session.json" "$WORK/session.bak"
rm "$WORK/home/alice/default/session.json"
run "$CLI" did publish --agent alice
expect_status "did publish with no token exits 1" 1
expect "  and names the way back" "no usable access token"
cp "$WORK/session.bak" "$WORK/home/alice/default/session.json"

# ---- 消息与通讯录 -------------------------------------------------------------

section "msg send — a direct message, alice -> bob"
run_quiet "$CLI" did show --agent bob --json
BOB_DID="$(field did)"
run "$CLI" msg send --agent alice --to "$BOB_DID" --text "hello bob"
expect_status "msg send is accepted" 0
expect "  and reports the target it resolved" "$BOB_DID"

section "contacts — a name for that DID, and the name coming back"
run "$CLI" contacts add --agent alice "$BOB_DID" --remark Bob
expect_status "contacts add succeeds" 0
run "$CLI" contacts resolve --agent alice Bob
expect_status "contacts resolve succeeds" 0
expect "  and gives back exactly the DID" "$BOB_DID"

# ---- 群 ----------------------------------------------------------------------

section "group create — a group in the service's own namespace"
run_quiet "$CLI" group create --agent alice --name "e2e 群" --json
expect_status "group create succeeds" 0
GROUP_DID="$(field group_did)"
echo "    group   $GROUP_DID"
case "$GROUP_DID" in
  "did:wba:${AUTHORITY}:g:"*)
    printf '    \033[32mok\033[0m   the group DID hangs under the service'\''s own authority\n' ;;
  *) printf '    \033[31mFAIL\033[0m the group DID is not under the service: %s\n' "$GROUP_DID"; FAILED=$((FAILED + 1)) ;;
esac

section "group info / members — and the name only I see"
run "$CLI" group info --agent alice "$GROUP_DID"
expect_status "group info succeeds" 0
expect "  and shows the group's own name" "e2e 群"
expect "  and has no remark line yet" "members:"
if grep -q "remark:" "$LAST_OUT"; then
  printf '    \033[31mFAIL\033[0m a remark line appeared before anything was named\n'
  FAILED=$((FAILED + 1))
else
  printf '    \033[32mok\033[0m   no remark line before anything was named\n'
fi

run "$CLI" group members --agent alice "$GROUP_DID"
expect_status "group members succeeds" 0
expect "  and lists the creator" "did:wba:${AUTHORITY}:user:alice:"

section "group set-remark — the other half of the address book (TODO6 §4.2)"
run "$CLI" group set-remark --agent alice "$GROUP_DID" Team
expect_status "set-remark succeeds" 0
run "$CLI" group info --agent alice "$GROUP_DID"
expect "  and group info now prints it next to the name" "remark:              Team"

run "$CLI" group set-remark --agent alice "$GROUP_DID" 作战组
expect "a rename replaces it in place" "作战组"
run "$CLI" group info --agent alice "$GROUP_DID"
expect "  and the new name is what shows" "remark:              作战组"

run "$CLI" group set-remark --agent alice "$GROUP_DID" --clear
expect "clearing says so" "forgot the remark for"
run "$CLI" group set-remark --agent alice "$GROUP_DID" --clear
expect "clearing twice is honest about there being nothing" "had no remark"
run "$CLI" group info --agent alice "$GROUP_DID"
if grep -q "remark:" "$LAST_OUT"; then
  printf '    \033[31mFAIL\033[0m the remark line survived a clear\n'
  FAILED=$((FAILED + 1))
else
  printf '    \033[32mok\033[0m   the remark line is gone after a clear\n'
fi

# 换一个身份给同一个群起名——两本册子按 owner_did 分开，谁的备注都不该串。
section "the remark book is per identity"
run "$CLI" group set-remark --agent bob "$GROUP_DID" BobsName
expect_status "bob may name the same group" 0
run "$CLI" group set-remark --agent alice "$GROUP_DID" AlicesName
expect_status "alice names it again" 0
run "$CLI" group info --agent alice "$GROUP_DID"
expect "  and alice sees her own name, not bob's" "remark:              AlicesName"
if grep -q "BobsName" "$LAST_OUT"; then
  printf '    \033[31mFAIL\033[0m one identity saw the other'\''s remark\n'
  FAILED=$((FAILED + 1))
else
  printf '    \033[32mok\033[0m   no bleed between the two books\n'
fi

# ---- 群的成员与改名 -----------------------------------------------------------
#
# 这几条是命令面上"写过但从没被跑过"的那部分（TODO6 §5.3 第二条）：`update-profile` 改的是
# **群自己的**名字（存在群的主机上、所有人一样），和上面那本只有自己看得见的册子不是一件事。

section "group join / leave — a second identity in the same group"
run "$CLI" group join --agent bob "$GROUP_DID"
expect_status "group join succeeds (the group is open-join by policy)" 0
expect "  and names the member it activated" "did:wba:${AUTHORITY}:user:bob:"
run "$CLI" group members --agent alice "$GROUP_DID"
expect "  and the group now lists bob" "did:wba:${AUTHORITY}:user:bob:"

section "group update-profile — the name everyone sees (P4 §7.4)"
run "$CLI" group update-profile --agent alice "$GROUP_DID" --name "改名后的群"
expect_status "group update-profile succeeds" 0
run "$CLI" group info --agent alice "$GROUP_DID"
expect "  and the group's own name has moved" "改名后的群"

section "group send — a message to the group, not to one member"
run "$CLI" group send --agent alice "$GROUP_DID" --text "hello group"
expect_status "group send is accepted" 0
expect "  and acknowledges the group it went to" "$GROUP_DID"

section "group leave — and the member list follows"
run "$CLI" group leave --agent bob "$GROUP_DID"
expect_status "group leave succeeds" 0
run "$CLI" group members --agent alice "$GROUP_DID"
if grep -q "did:wba:${AUTHORITY}:user:bob:" "$LAST_OUT"; then
  printf '    \033[31mFAIL\033[0m bob is still listed after leaving\n'
  FAILED=$((FAILED + 1))
else
  printf '    \033[32mok\033[0m   the leaver is gone from the member list\n'
fi

# ---- P6 ----------------------------------------------------------------------

section "group e2ee — the device side of P6"
run "$CLI" group e2ee publish --agent alice
expect_status "e2ee publish succeeds" 0
expect "  and names the key package it stored" "key package:"
run "$CLI" group e2ee create --agent alice "$GROUP_DID"
expect_status "e2ee create succeeds" 0
expect "  and starts the group at epoch 0" "epoch:               0"

# ---- 可选：对真 awiki 主机来一遍 ----------------------------------------------

if [ "$WITH_AWIKI" = 1 ]; then
  section "the same commands against the real awiki host ($AWIKI_URL)"
  if ! curl -sf "$AWIKI_URL/.well-known/did.json" >/dev/null; then
    printf '    \033[31mFAIL\033[0m nothing answers at %s/.well-known/did.json\n' "$AWIKI_URL"
    printf '         start it first — the command is in this script'\''s header\n'
    FAILED=$((FAILED + 1))
  else
    export AGENTXCLI_HOME="$WORK/awiki-home"
    # handle 是那台主机上唯一的，而且删不掉——带时间戳，脚本才跑得第二遍。
    AWIKI_AGENT="e2e-awiki-$(date +%s)"
    run "$CLI" did create --host "$AWIKI_URL" --handle "$AWIKI_AGENT" --agent "$AWIKI_AGENT"
    expect_status "did create succeeds against awiki" 0
    expect "  and awiki accepted the document" "registered with"
    run "$CLI" did publish --agent "$AWIKI_AGENT"
    expect_status "did publish succeeds against awiki" 0
    expect "  and nothing has changed, so it is a no-op" "already serves this document"

    # 真主机那半真正值钱的断言是这一条：文档改过之后，awiki 的 CAS + 我们自己的重签
    # 一起把版本推上去。玩具主机上也跑同样的动作，但那里 CAS 是我们自己写的。
    python3 - "$WORK/awiki-home/$AWIKI_AGENT/default/identity.json" <<'PY'
import json, sys
path = sys.argv[1]
document = json.load(open(path))
document["did_document"]["alsoKnownAs"] = ["https://e2e.invalid/on-awiki"]
json.dump(document, open(path, "w"), indent=1)
print("edited the stored document")
PY
    run "$CLI" did publish --agent "$AWIKI_AGENT"
    expect_status "an edited document publishes to awiki" 0
    expect "  and awiki moves the version 1 -> 2" "version: 1 -> 2"

    run "$CLI" me set --agent "$AWIKI_AGENT" --name "e2e on awiki"
    expect_status "me set succeeds against awiki" 0

    # ---- 负结果：这一条**要的就是失败**（TODO6 §5.3，`cli.md` §5）----------------
    #
    # awiki 实现的是**规范**，不是这个客户端的扩展面。所以对它读收件箱，正确的答复是
    # `-32601`——"我没有这个方法"。客户端的正确行为是把这句话原样报成
    # `unsupported_extension` 并退出 1：**不是**空收件箱，**不是**崩溃，也**不是**含糊的
    # 失败。这条断言最容易在重构里被悄悄改成"跳过"，所以它留在这儿，取值是**真主机**给的。
    run "$CLI" msg inbox --agent "$AWIKI_AGENT"
    expect_status "msg inbox against a spec-only peer exits 1" 1
    expect "  and reports the stable code a script branches on" "unsupported_extension"
    expect "  and says the peer does not implement it" "does not implement inbox.get"
    expect "  and quotes the peer's own code" "JSON-RPC error -32601"
  fi
fi

# ---- 收尾 --------------------------------------------------------------------

if [ "$FAILED" -eq 0 ]; then
  printf '\n\033[32mall checks passed\033[0m\n'
else
  printf '\n\033[31m%d check(s) failed\033[0m\n' "$FAILED"
  printf 'the host and the service logs are gone with the temp dir; re-run with the command\n'
  printf 'lines above to see them again\n'
fi
exit "$([ "$FAILED" -eq 0 ] && echo 0 || echo 1)"
