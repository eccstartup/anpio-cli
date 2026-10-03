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

# 直接查本地库并断言结果里有某个字符串（client-messages.md）。库是明文 sqlite，所以这条断言
# 不经过客户端任何读路径——它证明的正是"写进去的东西真的在文件里"。以只读方式打开：一个不该
# 存在的库不该被这条断言**创建**出来，它该让断言失败。
expect_db() {
  local why="$1" db="$2" sql="$3" needle="$4" got
  got="$(python3 -c '
import sqlite3, sys
try:
    conn = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
    print(conn.execute(sys.argv[2]).fetchall())
except Exception as err:
    print(f"ERROR: {err}")
' "$db" "$sql")"
  if printf '%s' "$got" | grep -qF -- "$needle"; then
    printf '    \033[32mok\033[0m   %s\n' "$why"
  else
    printf '    \033[31mFAIL\033[0m %s\n         in %s: %s\n         expected to find: %s\n' \
      "$why" "$db" "$got" "$needle"
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
run_quiet "$CLI" did show --agent alice --json
ALICE_DID="$(field did)"
run_quiet "$CLI" did show --agent bob --json
BOB_DID="$(field did)"
run "$CLI" msg send --agent alice --to "$BOB_DID" --text "hello bob"
expect_status "msg send is accepted" 0
expect "  and reports the target it resolved" "$BOB_DID"

# `--once` 是 realtime.md 给的那条逃生舱：回填、打印、退出 0。于是这条"唯一一个常驻进程"的命令
# 也能进脚本——不这么写，客户端最重的那条路就只有 `packages/e2e`（TS 那边）在跑。
# 断言的是**投递与读取是两件事**：`msg send` 只说明服务收下了，信在收件箱里是这里才知道的。
section "msg listen --once — the message was waiting, and reading it says so"
run "$CLI" msg listen --agent bob --once
expect_status "the one-shot listener exits 0" 0
expect "  and replays what was waiting before it ever connected" "hello bob"
expect "  and names the sender it came from" "$ALICE_DID"
expect "  and carries the delivery cursor, which is what dedupes a reconnect" '"seq":'

# 本地库（TODO5 §6 Phase 2 的写入侧）。上面两条命令各自落了一行，一边一行：`msg send` 在
# **成功之后**写发出的一侧，`msg listen` 在**消费**时写收到的一侧。最后一条断言是那个不变式
# 本身——落行与推游标在同一个事务里，所以两者必须相等，而且库是只读打开的。
section "messages.db — both sides kept a row, and the cursor followed the delivery"
expect_db "the sender kept its own row" "$WORK/home/alice/default/messages.db" \
  "SELECT direction, text FROM messages" "('out', 'hello bob')"
expect_db "the recipient kept the row it was delivered" "$WORK/home/bob/default/messages.db" \
  "SELECT direction, text FROM messages" "('in', 'hello bob')"
expect_db "and the local cursor is exactly the delivery it recorded" \
  "$WORK/home/bob/default/messages.db" \
  "SELECT applied_seq = (SELECT service_seq FROM messages WHERE direction = 'in') FROM sync_state" \
  "[(1,)]"

section "contacts — a name for that DID, and the name coming back"
run "$CLI" contacts add --agent alice "$BOB_DID" --remark Bob
expect_status "contacts add succeeds" 0
run "$CLI" contacts resolve --agent alice Bob
expect_status "contacts resolve succeeds" 0
expect "  and gives back exactly the DID" "$BOB_DID"

# 这是"Agent 能替人发消息"那句话的机器形态：**输入是名字，不是 DID**。
# 名字进发现是块垒（§3.3）：DID 形状的参数直接走发现，其余只有册子能翻。
section "msg send --to <name> — the address book is what turns a name into a DID"
run "$CLI" msg send --agent alice --to Bob --text "hello by name"
expect_status "msg send accepts the name the book just learned" 0
expect "  and prints the DID the name resolved to" "$BOB_DID"
expect "  and says it was a name, not a DID" "named:"

# 册子上没有的名字是**拒绝**，不是"发给自己"或"发给某个候选人"。
section "a name nobody has is refused, and the refusal names the fix"
run "$CLI" msg send --agent alice --to Nobody --text "hello nobody"
expect_status "an unknown name exits 1" 1
expect "  and says no contact has that name" "no contact named"
expect "  and names the command that adds one" "contacts add"

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
#
# 这四条控制方法此前只有"手工跑过"没有"脚本跑过"（TODO6 §5.3 第二条记的缺口）。
#
# `e2ee add` 加的是**成员的设备**，所以 bob 得先在群里——他在上面退过了，这里让他重新加入，
# 那正是这个群 `open-join` 策略允许的事。
#
# 一条 KeyPackage 是**一次性的**：`get_key_package` 在挑的同时就把它占住（§8.2.4 L767 的
# MAY，服务确实这么做），所以"读一枚来断言"与"让 add 拿走一枚"是两次消耗，bob 要发布两枚。

section "group e2ee publish — each device publishes its own key package"
run_quiet "$CLI" group join --agent bob "$GROUP_DID"
run_quiet "$CLI" did show --agent bob --json
BOB_DEVICE="$(field device_id)"

run "$CLI" group e2ee publish --agent alice
expect_status "e2ee publish succeeds" 0
expect "  and names the key package it stored" "key package:"

# 负结果：柜子里没有可发的，正确的答复是**拒绝**（5000 `key_package_not_found`），
# 不是一个空的成功。§8.2.4 L763 把它与"某一枚已被用过"（5012）分开，因为调用方该做的事不同。
section "an empty cabinet is a refusal, not an empty answer"
run "$CLI" group e2ee get-key-package --agent alice --target-did "$BOB_DID" --target-device "$BOB_DEVICE"
expect_status "get-key-package with nothing published exits 1" 1
expect "  and names the peer code" "key_package_not_found"

run "$CLI" group e2ee publish --agent bob
expect_status "the second device publishes its own key package" 0
run "$CLI" group e2ee publish --agent bob
expect_status "and a second one, because a package is single-use" 0

section "group e2ee create — the group starts encrypted at epoch 0"
run "$CLI" group e2ee create --agent alice "$GROUP_DID"
expect_status "e2ee create succeeds" 0
expect "  and starts the group at epoch 0" "epoch:               0"

section "group e2ee get-key-package — reading a peer device's published package"
run "$CLI" group e2ee get-key-package --agent alice --target-did "$BOB_DID" --target-device "$BOB_DEVICE"
expect_status "get-key-package succeeds" 0
expect "  and names the peer it read from" "$BOB_DID"
expect "  and prints the package it holds" "key package:"

section "group e2ee add / send / remove — one device's life inside the encrypted group"
run "$CLI" group e2ee add --agent alice "$GROUP_DID" --member-did "$BOB_DID" --member-device "$BOB_DEVICE"
expect_status "e2ee add succeeds" 0
expect "  and reports the member it added" "$BOB_DID"
expect "  and advances the group to epoch 1" "epoch:               1"

run "$CLI" group e2ee send --agent alice "$GROUP_DID" --text "encrypted hello"
expect_status "e2ee send is accepted" 0
expect "  and acks the group it encrypted for" "$GROUP_DID"

run "$CLI" group e2ee remove --agent alice "$GROUP_DID" --member-did "$BOB_DID" --member-device "$BOB_DEVICE"
expect_status "e2ee remove succeeds" 0
expect "  and advances the group to epoch 2" "epoch:               2"

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
    # awiki 实现的是**规范**，不是这个客户端的扩展面。所以对它要扩展面上的东西，正确的答复
    # 是 `-32601`——"我没有这个方法"。客户端的正确行为是把这句话原样报成
    # `unsupported_extension` 并退出 1：**不是**空收件箱，**不是**崩溃，也**不是**含糊的
    # 失败。这条断言最容易在重构里被悄悄改成"跳过"，所以它留在这儿，取值是**真主机**给的。
    #
    # 拿来做这件事的是 `msg fetch`，不是 `msg inbox`：读这一族搬回本地之后（TODO7 §2），
    # `msg inbox` 根本不问服务，拿它去撞一台只有规范的主机什么也证明不了——它会照样答完
    # 本地的记录再退出 0。**唯一**会去问服务的是 `msg fetch`，也就是这一条。
    run "$CLI" msg fetch --agent "$AWIKI_AGENT"
    expect_status "msg fetch against a spec-only peer exits 1" 1
    expect "  and reports the stable code a script branches on" "unsupported_extension"
    expect "  and says the peer does not implement it" "does not implement sync.delta"
    expect "  and quotes the peer's own code" "JSON-RPC error -32601"
  fi
fi

# ---- 换钥：信箱跟着人走 --------------------------------------------------------
#
# TODO7 §5 那条"对端换钥后一直不来信的那一半"。量的是一整条链上的四件事：换钥这件事本身
# （`did update` 把旧文档标成退休、把新文档立起来）、旧 DID 的处置（`did resolve` 说它
# 不是当前的那个，`--chain` 说出后继是谁）、发信那一侧的实情（按旧 DID 发信**不会失败**——
# 收件人是当时那个 DID，一个还在服务手上的字符串），以及最要紧的那一件：**换钥之后投到旧
# DID 名下的信，会不会自己找到人**。
#
# 最后一件有个时间上的前提，别处没写过：服务发现"对端换了 DID"的时延上界**就是** DID 文档
# 缓存的 TTL（`config.ts` 的 `DEFAULT_DID_CACHE_TTL_MS` 那一段说的正是这件事——缓存里那份
# 文档是换钥**之前**抓的，它自己不可能写着后来才发生的事，所以链只能等缓存过期再走一次）。
# 这一节把服务**用一个 1 毫秒的 TTL 重启一次**：它量的是"换钥之后信会不会回来"，不是
# "五分钟有多长"。别处跑的一直是出厂的那个数——这条只在这一节里成立。
section "did update — a peer rotates its key, and the DID string moves with it"

export AGENTXCLI_HOME="$WORK/home"
for name in dave erin; do
  run "$CLI" did create --host "http://localhost:${HOST_PORT}" --handle "$name" --agent "$name"
  expect_status "did create $name succeeds" 0
done
run_quiet "$CLI" did show --agent dave --json
DAVE_OLD="$(field did)"
run_quiet "$CLI" did show --agent erin --json
ERIN_DID="$(field did)"

run "$CLI" contacts add --agent erin "$DAVE_OLD" --remark Dave
expect_status "erin's book learns dave under the DID he has now" 0

run "$CLI" msg send --agent erin --to "$DAVE_OLD" --text "before the rotation"
expect_status "the message before the rotation is accepted" 0

# dave 取一次件。这一步顺带把水位线（`account_dids`）压在他**现在**这个 DID 上——后面那句
# "换钥之后他没再取过件"才有对照物。
run "$CLI" msg listen --agent dave --once
expect_status "dave reads it" 0
expect "  and the message was there to read" "before the rotation"

# 真的换一次钥。`--target` 是 ANP-03 §2.5.3 的要求：那条只定义了这次交付的**形状**，没有
# 定义管理接口的路径，所以路径由主机的运维说了算——玩具主机演的那个见 `did_host.py`。
run "$CLI" did update --agent dave --target "http://localhost:${HOST_PORT}/user-service/v1/did/update"
expect_status "the host accepts the rotation" 0
expect "  and names the DID it retired" "retiring did:"
expect "  and the one that takes over" "successor did:"

run_quiet "$CLI" did show --agent dave --json
DAVE_NEW="$(field did)"
if [ -n "$DAVE_NEW" ] && [ "$DAVE_NEW" != "$DAVE_OLD" ]; then
  printf '    \033[32mok\033[0m   the local identity signs as a different DID now\n'
else
  printf '    \033[31mFAIL\033[0m did update left the DID as it was (%s)\n' "$DAVE_NEW"
  FAILED=$((FAILED + 1))
fi

section "did resolve — the retired DID says so, and --chain names the successor"
run "$CLI" did resolve "$DAVE_OLD"
expect_status "did resolve on a retired DID exits 2" 2
expect "  and says the document is not current" "superseded: yes"
expect "  and points at the flag that follows the link" "--chain"

run "$CLI" did resolve --chain "$DAVE_OLD"
expect_status "did resolve --chain exits 2 too — the question was answered, not failed" 2
expect "  and walks to the DID dave signs as now" "$DAVE_NEW"
expect "  and reports how strong that hop was" "assurance:  verified"

# 换钥是**对端**的事，本地的册子和发现都不会自己变——这正是问题里"我这边还记着旧的"那句。
run "$CLI" contacts resolve --agent erin Dave
expect_status "erin's book still answers for dave" 0
expect "  and it is still the DID he left behind" "$DAVE_OLD"

# 重启，把这个节的前提摆明（见上面那段）。日志用 `>>` 续写，前面那些行还留着。
kill "$SERVICE_PID" 2>/dev/null || true
wait "$SERVICE_PID" 2>/dev/null || true
AGENTX_LISTEN="127.0.0.1:${SERVICE_PORT}" \
AGENTX_PUBLIC_URL="http://127.0.0.1:${SERVICE_PORT}" \
AGENTX_SERVICE_DID="$SERVICE_DID" \
AGENTX_DB="$WORK/svc/svc.db" \
AGENTX_OBJECT_DIR="$WORK/svc/objects" \
AGENTX_DID_DEV_HOSTS="127.0.0.1,localhost" \
AGENTX_DID_CACHE_TTL_MS=1 \
  node "$ROOT/packages/service/dist/main.js" >>"$WORK/svc.log" 2>&1 &
SERVICE_PID=$!
wait_for_port "$SERVICE_PORT" "the service"

section "the mailbox follows the key — mail sent to the retired DID comes home"
# 按**旧 DID** 发信。断言的是"服务收下了"，不是"被拒了"：收件人是那个 DID 本身，而它还在
# 服务手上，所以这一步不会失败——问题里"按 DID 发信失败"那句话，就是在这里被证伪的。
run "$CLI" msg send --agent erin --to "$DAVE_OLD" --text "sent to the retired DID"
expect_status "a send to the retired DID is still accepted" 0
expect "  and the target is the DID erin still holds" "$DAVE_OLD"

# 这就是"别让它悬着"。`sync.delta` 是自址请求，服务在这条路上顺带把旧 DID 名下的投递挪到
# 新 DID 名下，于是那条信出现在 dave **自己**那个信箱里。
run "$CLI" msg listen --agent dave --once
expect_status "dave's next read exits 0" 0
expect "  and the message sent to the DID he left behind is in his queue" "sent to the retired DID"

run "$CLI" msg inbox --agent dave
expect_status "dave's inbox answers" 0
expect "  and holds the message sent to the old DID" "sent to the retired DID"
expect "  and holds the one from before the rotation too" "before the rotation"

# 上面那两条读的是**效果**；这一条读的是**那件事本身**——服务记了它挪了什么。只有它有这句
# 话，才能把"读到了"和"它本来就该读到"分开。
if grep -qF "mailbox of ${DAVE_OLD} -> ${DAVE_NEW}" "$WORK/svc.log"; then
  printf '    \033[32mok\033[0m   the service moved the deliveries to the successor\n'
else
  printf '    \033[31mFAIL\033[0m the service never logged moving %s to %s\n' "$DAVE_OLD" "$DAVE_NEW"
  FAILED=$((FAILED + 1))
fi

# ---- 只有 fetch 会联网 --------------------------------------------------------
#
# 这是"读搬到本地"那句裁定（TODO7 §2）的**可断言形态**。上面每一节验证的都是"有服务时读
# 得对"，而这一节验证的是那句裁定本身：把服务杀掉，读这一族照样答，全靠本地那份记录——
# 唯一会去敲网络的是 `msg fetch`，它必须**明确**失败，并且说清自己是那一条。
#
# 这条断言如果不是在这里、而是靠"读命令里没写网络调用"来保证，就会在下次重构里被悄悄
# 推翻：读路径上加一次发现调用是很容易的，而那时候全绿。
section "only msg fetch goes online — the read family answers with the service killed"

# carol 的身份是在服务还活着的时候建的，但从头到尾**没连过**它——她的本地库一行都没有。
# "读不写文件"这条只有在她身上才查得出来：bob 的库早就存在了，光看存在与否分不出读和写。
export AGENTXCLI_HOME="$WORK/home"
run_quiet "$CLI" did create --host "http://localhost:${HOST_PORT}" --handle carol --agent carol
expect_status "did create carol succeeds while the service is still up" 0
CAROL_DIR="$WORK/home/carol/default"

kill "$SERVICE_PID" 2>/dev/null || true
wait "$SERVICE_PID" 2>/dev/null || true
SERVICE_PID=""

run "$CLI" msg inbox --agent carol --json
expect_status "msg inbox answers with no service at all" 0
expect "  and says the local record is empty rather than failing" '"messages": []'
if [ -e "$CAROL_DIR/messages.db" ]; then
  printf '    \033[31mFAIL\033[0m a read created a database\n'
  FAILED=$((FAILED + 1))
else
  printf '    \033[32mok\033[0m   reading wrote no file\n'
fi

run "$CLI" msg inbox --agent bob
expect_status "msg inbox still answers for an identity that has a record" 0
expect "  and is answered out of that record" "hello bob"

run "$CLI" msg history --agent bob "$ALICE_DID"
expect_status "msg history answers offline too" 0
expect "  and finds the thread by the peer's DID alone" "hello bob"

run_quiet "$CLI" msg inbox --agent bob --json
# 按**正文**挑那一行，不按位置：这个库是好几节一起攒出来的，`messages[0]` 是"最近的一条"，
# 往上再添一条别的话，这条断言就会指着一个跟它无关的 id 还全绿。正文在 `body` 里
# （`main.rs::row_of_stored`），文本消息的那个键就叫 `text`。
BOB_MSG_ID="$(python3 -c '
import json, sys
rows = json.load(open(sys.argv[1]))["messages"]
print(next(row["message_id"] for row in rows if (row.get("body") or {}).get("text") == "hello bob"))
' "$LAST_OUT")"
run "$CLI" msg show --agent bob "$BOB_MSG_ID"
expect_status "msg show answers offline" 0
expect "  and prints the row itself" "hello bob"

run "$CLI" msg read --agent bob --all
expect_status "msg read is a local write, so it needs no service" 0

# 反过来那一半：联网的那一条**必须**失败，而且第一行就得点名自己。没有这句上下文，
# 断网时的 `error sending request` 读起来像是"本地记录坏了"——而记录恰恰是还好着的那件东西。
run "$CLI" msg fetch --agent bob
expect_status "msg fetch fails with the service down" 1
expect "  and says it is the one that goes online" "the one read that goes online"
expect "  and names the commands that do not" "msg inbox"

# ---- 收尾 --------------------------------------------------------------------

if [ "$FAILED" -eq 0 ]; then
  printf '\n\033[32mall checks passed\033[0m\n'
else
  printf '\n\033[31m%d check(s) failed\033[0m\n' "$FAILED"
  printf 'the host and the service logs are gone with the temp dir; re-run with the command\n'
  printf 'lines above to see them again\n'
fi
exit "$([ "$FAILED" -eq 0 ] && echo 0 || echo 1)"
