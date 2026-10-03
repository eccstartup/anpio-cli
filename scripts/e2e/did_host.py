#!/usr/bin/env python3
"""e2e 的玩具 DID 主机：一台只做 DID 主机该做的那几件事的 HTTP 服务（脚手架，不是产品）。

**为什么不让本机 awiki 当这台主机。** awiki 只肯发**端点指向它自己**的文档
（TODO2 的 A7 / TODO5 §6），而 e2e 的后半截（`msg` / `group` / `group e2ee`）要打的是
**本仓的 `packages/service`**——awiki 没有 P6，也不能让一份文档的 `serviceEndpoint`
指着别处。`packages/e2e/src/harness.ts` 起玩具主机的理由与此逐字相同，这里是同一个决定
的 Rust 侧版本。awiki 的角色因此只剩前半截：`did create` / `did publish` / `me` 对**真主机**
跑一遍，看它收不收我们的文档（那正是那几条命令存在的意义）。

它做的事就是 CLI 真的会发的那些请求，不多一件：

  * `GET  /.well-known/did.json`             主机自己的 `serviceDid` 与消息端点
  * `GET  /<DID 推出来的路径>`                把存下的文档发回去
  * `GET  /g/<id>/did.json`                  **转发给服务**——群文档那一半
  * `POST /user-service/v1/did-auth/rpc`     `register` / `update_document`
  * `POST /user-service/v1/did/profile/rpc`  `get_me` / `update_me`
  * `POST /user-service/v1/did/update`       一次 `did update` 的两个文档（ANP-03 §2.5.3）
  * `POST …/did/update-lost-answer`          同上，收下之后**不回应**就断（回程丢了）
  * `POST …/did/update-lost-request`         什么也不做、也不回应就断（请求丢了）
  * `POST /user-service/v1/did/update-refused` 同上，收下之后**明确说不**（HTTP 403）
  * `POST /`                                 ANP-02 的登录：先 401 给一个 nonce，答对了才发 token

路径没有第二个约定：`didToUrl`（`packages/core/src/crypto/resolveDid.ts:498`）说
`did:wba:<authority>[:<seg>…]` 住在 `/<seg…>/did.json`，所以 DID 自己说了它挂在哪。

**关于那条转发。** 群 DID 是 `serviceDid + ":g:" + <id>`，所以它和身份 DID 落在**同一个权威段**
下面——而按 `groups.md` §2.2，群文档是由**服务**发布的（群就住在服务的命名空间里）。真部署里
这两件事同属一个权威（awiki 自己既是主机又是消息服务），所以那里没有转发这一步。这台玩具主机
把权威段演成两个进程，于是它必须把 `/g/…` 这一条让给服务——那不是绕过什么，正是"同一个域下面，
群文档归服务管"这句话在两个进程下的样子。

**文档由客户端造**（`did create` 本地生成再 `register`），主机只负责按 DID 存、按 DID 发——
所以这里没有一处签名逻辑，也没有一处"替客户端编一份文档"。少掉这两件事正是它能当
"一台干净的主机"用的原因。
"""

import argparse
import base64
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DID_AUTH_PATH = "/user-service/v1/did-auth/rpc"
DID_PROFILE_PATH = "/user-service/v1/did/profile/rpc"
# ANP-03 §2.5.3 不定管理接口的路径，所以 `did update --target` 自己指一个——真部署里这个 URL
# 由那台主机的运维说了算，这里就挑一个和上面两条同族的。
DID_UPDATE_PATH = "/user-service/v1/did/update"
# 交付在**半路上**断掉时的那两条。ANP-03 §2.5.3 定义的是交付的**形状**，没定义"失败长什么样"，
# 所以这两个不是从规范里抄来的路径，是这台玩具主机**演出来的两种失败**——`did update` 的三种
# 结局里独有的那一种（`Ambiguous`：送出去了，但对方收没收**不可知**）需要它才跑得出来：
#
#   * `-lost-answer`：文档**已经收下**（真的换了），回程却断了。客户端那一侧只看见
#     "不知道对方收没收到"，而实际上收到了——这正是 `--resume` 存在的理由。
#   * `-lost-request`：请求到了这儿，可是一件事都没做就断了。同样"不知道"，实际没落地。
#
# 两条都**一个字节都不回**就断开（见 `Handler.do_POST`）：客户端读到的既不是 2xx 也不是一个
# 错误状态，于是落到"不可知"那一档。回一个 500 就不是这个意思了——那叫**确定**没落地
# （`Settled`），而"确定"那一条本来就有别的办法演。
DID_UPDATE_LOST_ANSWER_PATH = "/user-service/v1/did/update-lost-answer"
DID_UPDATE_LOST_REQUEST_PATH = "/user-service/v1/did/update-lost-request"
# 第三条路：主机**明确说不**（HTTP 403）。它与上面两条是**相反**的结局——一个有字节回来、
# 一个没有——而这条线把它们分得很开：没有任何回应 = 收没收不可知（那把钥要留着），一个非 2xx
# 的回应 = **确定**没落地（那把钥可以丢）。少一条，"确定"那一档就只能靠猜。
DID_UPDATE_REFUSED_PATH = "/user-service/v1/did/update-refused"
# ANP-02 的登录端点。路径是**根**：`main.rs::host_and_token` 告诉用户的 `--target` 就是存下来的
# `did_host`（`http://localhost:<port>`），所以 `anp login --target <did_host>` 打的是这个根。
#
# 它要演的是**401 挑战**那一次往返：第一次不带 nonce，主机答 401 并给出**自己**的 nonce；客户端
# 拿这个 nonce 重签一次再来，才对。这不是可有可无的一步——`post_signed` 的整个重试逻辑
# （`MAX_ATTEMPTS = 2`）只在这条路上跑得到，而它是唯一"签名覆盖了服务器给的东西"的地方。
LOGIN_PATH = "/"


def jcs(value) -> bytes:
    """RFC 8785 的那一步：排序键 + 无空格 + 不转义非 ASCII。与 Rust 侧的
    `serde_json_canonicalizer` 对同一批文档给出同一串字节，所以哈希对得上。"""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def document_hash(document) -> str:
    """`host.rs::document_hash` 的同一件事：`sha256:<base64url-nopad>`。

    客户端拿它做 CAS（"我上次读到的那一版还在不在"），所以这里必须逐字节同款，
    否则 `did publish` 的第二次永远会说自己看到的是另一版。"""
    digest = hashlib.sha256(jcs(document)).digest()
    return "sha256:" + base64.urlsafe_b64encode(digest).decode().rstrip("=")


def path_for(did: str) -> str:
    """DID → 它该被发在的路径。`did:wba:127.0.0.1%3A9002:user:carol:e1_x`
    → `/user/carol/e1_x/did.json`；主机自己的 DID（没有路径段）→ `/.well-known/did.json`。"""
    match = re.match(r"^(?:did:web|did:wba):(.+)$", did)
    if match is None:
        raise ValueError(f"not a did:web/did:wba DID: {did}")
    segments = match.group(1).split(":")
    if any(segment == "" for segment in segments):
        raise ValueError(f"DID with an empty segment: {did}")
    tail = segments[1:]
    if not tail:
        return "/.well-known/did.json"
    return "/" + "/".join(tail) + "/did.json"


class State:
    """主机的全部状态。一个进程一份，跑完即弃——不起库、不落盘。"""

    def __init__(self, authority: str, service_did: str, service_endpoint: str):
        self.authority = authority
        self.service_did = service_did
        self.service_endpoint = service_endpoint
        # 群文档转发去哪儿：端点去掉 `/anp-im/rpc` 就是服务的源。
        self.service_origin = service_endpoint[: -len("/anp-im/rpc")]
        # 路径 → 文档，以及路径 → 版本号（`did publish` 的 CAS 拿它做进步）
        self.documents: dict[str, dict] = {}
        self.versions: dict[str, int] = {}
        # bearer token → 它属于哪个 DID。真主机是这么回事，`update_document` / `me` 都靠它。
        self.tokens: dict[str, str] = {}
        self.profiles: dict[str, dict] = {}
        # 登录那次挑战发出去的 nonce（还没被用掉的那个）。**一次只有一个**，因为一次挑战只
        # 该被答一次——服务端留着它，是为了让"客户端到底有没有拿这个 nonce 回来"成为一个
        # 可断言的事实，而不是一句相信。
        self.login_nonce: str | None = None
        self.login_challenges = 0

    def well_known(self) -> dict:
        """主机自己的文档。`fetch_host_service` 从这里读 `serviceDid` 与消息端点，
        再把它们写进**身份**的文档里——所以这台主机说什么，身份就指向什么。"""
        return {
            "id": f"did:wba:{self.authority}",
            "service": [
                {
                    "id": f"did:wba:{self.authority}#anp-message",
                    "type": "ANPMessageService",
                    "serviceEndpoint": self.service_endpoint,
                    "serviceDid": self.service_did,
                }
            ],
        }


def rpc_result(request_id, result) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def rpc_error(request_id, code: int, message: str, named: str) -> dict:
    """`data.type` 是客户端真正分支的那个字符串（`host.rs::call` 读的就是它），
    数字码只是陪衬——真主机也是这么答的。"""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message, "data": {"type": named}},
    }


def handle_auth_rpc(state: State, method: str, params: dict, token: str | None, request_id):
    if method == "register":
        document = params.get("did_document")
        if not isinstance(document, dict) or "id" not in document:
            return None, rpc_error(request_id, -32602, "did_document is required", "invalid_params")
        did = document["id"]
        path = path_for(did)
        if path in state.documents:
            # 与真主机同款：重复注册是**冲突**，不是 upsert。丢了回执要用 `update_document`
            # （那正是 `did publish` 的用途）。
            return None, rpc_error(request_id, 409, "this DID is already registered", "did_already_registered")
        state.documents[path] = document
        state.versions[path] = 1
        issued = f"e2e-token-{did}"
        state.tokens[issued] = did
        state.profiles.setdefault(did, {"did": did, "handle": params.get("handle", "")})
        return (
            {
                "access_token": issued,
                "token_type": "Bearer",
                "did": did,
                "handle": params.get("handle", ""),
                "document_version": 1,
                "state": "active",
            },
            None,
        )

    if method == "update_document":
        did = state.tokens.get(token or "")
        if did is None:
            return None, rpc_error(request_id, 401, "a bearer token is required", "unauthorized")
        path = path_for(did)
        served = state.documents.get(path)
        if served is None:
            return None, rpc_error(request_id, 404, "no document for this DID", "did_not_registered")
        expected = params.get("expected_document_hash")
        if expected != document_hash(served):
            # CAS 拒绝——这是 `did publish` 那个"我读到的是不是还是这一版"的问句的**否定**答案，
            # 所以 e2e 必须能把它演出来，不然那半条语义没有测试咬住。
            return None, rpc_error(
                request_id, 409, "the served document is not the one you read", "did_document_changed"
            )
        document = params.get("document")
        if not isinstance(document, dict) or document.get("id") != did:
            return None, rpc_error(request_id, -32602, "document.id must be this DID", "invalid_params")
        state.documents[path] = document
        state.versions[path] += 1
        return (
            {"did": did, "document_version": state.versions[path], "document": document},
            None,
        )

    return None, rpc_error(request_id, -32601, f"unknown method {method}", "method_not_found")


def handle_profile_rpc(state: State, method: str, params: dict, token: str | None, request_id):
    did = state.tokens.get(token or "")
    if did is None:
        return None, rpc_error(request_id, 401, "a bearer token is required", "unauthorized")
    profile = state.profiles.setdefault(did, {"did": did})

    if method == "get_me":
        # `did_document` 与 `document_version` 是 `did publish` 读的那两栏（它拿前者的哈希
        # 做 CAS），不是可选的装饰。
        served = state.documents[path_for(did)]
        return (
            {
                **profile,
                "did_document": served,
                "document_version": state.versions[path_for(did)],
            },
            None,
        )

    if method == "update_me":
        # 只写递过来的键——这正是"设昵称不会把头像抹掉"那条说法的落点。
        for key in ("display_name", "description", "avatar_uri", "profile_uri"):
            if key in params:
                profile[key] = params[key]
        return (profile, None)

    return None, rpc_error(request_id, -32601, f"unknown method {method}", "method_not_found")


class Handler(BaseHTTPRequestHandler):
    state: State  # 由 `serve()` 注入

    def log_message(self, fmt, *args):  # 默认会往 stderr 刷每一行访问日志，太吵
        pass

    def send_json(self, status: int, payload, headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 —— BaseHTTPRequestHandler 的约定
        path = self.path.split("?", 1)[0]
        if path == "/.well-known/did.json":
            self.send_json(200, self.state.well_known())
            return
        if path.startswith("/g/") and path.endswith("/did.json"):
            # 群的文档归服务管（`groups.md` §2.2），不是这台主机存的——见文件头那条转发。
            self.forward_group_document(path)
            return
        document = self.state.documents.get(path)
        if document is None:
            self.send_json(404, {"error": "no document at this path"})
            return
        body = json.dumps(document).encode()
        self.send_response(200)
        # `application/did+json`：解析器只认它与 `application/json`，换个拼法会被判成
        # "取回来的不是文档"。
        self.send_header("content-type", "application/did+json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def apply_update(self, envelope):
        """把一次 `did update` 送来的两个文档落下去。返回 `(status, payload)`，**不发**。

        分成"改"与"答"两步，是因为那两个半路的端点（见上面那两个常量）要的正是"改了但不答"
        ——把写响应留在调用方手里，比在函数里塞一个 `answer=False` 的开关诚实：这里本来就只
        有一件事（按 DID 存），发不发出去是另一个人做的另一个决定。
        """
        retirement = envelope.get("didDocument")
        retiring_did = envelope.get("did")
        successor_did = envelope.get("successorDid")
        successor_document = envelope.get("successorDocument")
        if not isinstance(retirement, dict) or not isinstance(successor_document, dict):
            return 400, {"error": "didDocument and successorDocument are required"}
        if not isinstance(retiring_did, str) or not isinstance(successor_did, str):
            return 400, {"error": "did and successorDid are required"}
        old_path = path_for(retiring_did)
        if self.state.documents.get(old_path) is None:
            return 404, {"error": f"no document for {retiring_did}"}
        # 两个文档都必须指着同一个后继，否则这就是一次把 A 退休、把 B 抬上去的交付——
        # 收下它等于让这台主机替客户端编一份自相矛盾的账。
        if retirement.get("successorDid") != successor_did or successor_document.get("id") != successor_did:
            return 400, {"error": "successorDid must be the one both documents name"}
        self.state.documents[old_path] = retirement
        self.state.versions[old_path] += 1
        new_path = path_for(successor_did)
        self.state.documents[new_path] = successor_document
        self.state.versions[new_path] = 1
        self.state.tokens[f"e2e-token-{successor_did}"] = successor_did
        self.state.profiles.setdefault(successor_did, {"did": successor_did, "handle": ""})
        return 200, {"did": retiring_did, "successorDid": successor_did}

    def handle_update(self, envelope) -> None:
        """ANP-03 §2.5.3 的更新端点：一次 `did update` 送来的两个文档落在这里。

        **它不验签，这是它的合同，不是它的疏漏。** 文件头那段写着这台主机一处签名逻辑都没有，
        它只按 DID 存、按 DID 发。"这次转移是不是真的"由**读链的人**核：`resolve_chain` 会验
        退休文档上 key-1 的 proof，验不过就走不到后继。所以主机收下的是一份客户端已经签好的
        文档，判断对错不属于它——真主机（awiki）在这里是权威，要防伪造、防重放；这台演戏的
        主机不演那一层。

        它做的唯一一件事是把两份文档放到真主机会放的位置：退休文档盖住**旧 DID** 那条路径，
        后继文档占住**新 DID** 那条。少了这一手，`did update` 的客户端那一侧就没有一个
        "换过钥之后的世界"可跑——而那正是 e2e 要咬的东西。
        """
        self.send_json(*self.apply_update(envelope))

    def forward_group_document(self, path: str) -> None:
        url = f"{self.state.service_origin}{path}"
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                body = response.read()
                content_type = response.headers.get("content-type", "application/json")
        except urllib.error.HTTPError as error:
            # 服务说没有这个群就照原样传回去（404 是它的答复，不是这台主机的毛病）。
            self.send_json(error.code, {"error": f"the service answered HTTP {error.code}"})
            return
        except OSError as error:
            self.send_json(502, {"error": f"could not reach the service at {url}: {error}"})
            return
        self.send_response(200)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_login(self, body) -> None:
        """ANP-02 的登录：**先挑战，再发 token**（ANP-02 §3.2）。

        三次判断，一次往返一步：

          1. 请求没带 nonce → 主机答 **401**，并在 `WWW-Authenticate` 里给一个**它自己的**
             nonce。这就是挑战。
          2. 请求带着那个 nonce 回来 → 答 **200** 与 token。走到这里就说明客户端**重签过**
             一次，且签名覆盖的是服务器给的值。
          3. 请求带着一个主机从没发过的 nonce 进来 → 答 **401 且不再给挑战**。一个"再挑战一次"
             的服务器不是在要 nonce，是在拒绝（`request.rs` 的注释里就是这么写的），所以这里
             不给第二个 nonce——那条路也正是客户端把 401 当成失败上报的那条。

        这三条都往 stdout 打一行。日志不是调试残渣：`scripts/e2e.sh` 靠它断言**服务端看见了
        哪一次往返**——客户端说自己登录成功了，与"主机真的收到了那个 nonce"，是两件事。
        """
        did = body.get("did")
        if not isinstance(did, str) or self.state.documents.get(path_for(did)) is None:
            # 不认识的 DID 不发 token——这台主机只肯为它存过文档的身份背书。
            self.send_json(404, {"error": "no document for this DID"})
            return

        nonce = body.get("nonce")
        nonce = nonce if isinstance(nonce, str) else ""

        if nonce == "":
            self.state.login_challenges += 1
            self.state.login_nonce = f"e2e-challenge-{self.state.login_challenges}"
            print(f"login: challenged {did} with {self.state.login_nonce}", flush=True)
            self.send_json(
                401,
                {"error": "a nonce is required"},
                {"WWW-Authenticate": f'ANP realm="did", nonce="{self.state.login_nonce}"'},
            )
            return

        if nonce == self.state.login_nonce:
            self.state.login_nonce = None
            print(f"login: accepted the challenge for {did}", flush=True)
            self.send_json(
                200,
                {
                    "token": f"e2e-token-{did}",
                    "token_type": "Bearer",
                    "did": did,
                    "docUrl": f"http://{self.headers.get('Host', 'localhost')}{path_for(did)}",
                },
            )
            return

        print(f"login: refused a nonce it never issued ({nonce})", flush=True)
        self.send_json(401, {"error": "this nonce is not one this host issued"})

    def do_POST(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("content-length", "0"))
        try:
            envelope = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self.send_json(400, {"error": "the body was not JSON"})
            return
        method = envelope.get("method", "")
        params = envelope.get("params", {}) or {}
        request_id = envelope.get("id")
        authorization = self.headers.get("authorization", "")
        token = authorization[7:] if authorization.lower().startswith("bearer ") else None

        if path == LOGIN_PATH:
            # 根路径是 ANP-02 的登录端点，不是 JSON-RPC——所以它读的是**平铺的**那一份体
            # （`{nonce, did, didDocument}`），而不是下面那些 `{method, params}` 信封。
            self.handle_login(envelope)
            return
        if path == DID_UPDATE_PATH:
            self.handle_update(envelope)
            return
        if path in (DID_UPDATE_LOST_ANSWER_PATH, DID_UPDATE_LOST_REQUEST_PATH):
            # 见那两个常量：`-lost-answer` 把文档收下（真的换了），`-lost-request` 一件事都不做。
            # 两条都**不回应**就断——那个空白的回程正是"不可知"的全部内容。`close_connection`
            # 让 http.server 在这一轮之后关掉连接，于是客户端读到的是 EOF 而不是任何状态码。
            if path == DID_UPDATE_LOST_ANSWER_PATH:
                self.apply_update(envelope)
            self.close_connection = True
            return
        if path == DID_UPDATE_REFUSED_PATH:
            # 有回应，而且是个"不"。客户端因此**确定**这次交付没落地——与上面两条正好相反，
            # 它是"那把钥可以丢掉"的那一档的证据。
            self.send_json(403, {"error": "this DID server does not accept ownership transfers"})
            return
        if path == DID_AUTH_PATH:
            result, error = handle_auth_rpc(self.state, method, params, token, request_id)
        elif path == DID_PROFILE_PATH:
            result, error = handle_profile_rpc(self.state, method, params, token, request_id)
        else:
            result, error = None, rpc_error(request_id, -32601, "no such path", "method_not_found")

        if error is not None:
            # 与真主机一致：类型化错误既走 HTTP 状态码，也走 JSON-RPC 的 error 体。
            self.send_json(409 if error["error"]["code"] == 409 else 200, error)
            return
        self.send_json(200, rpc_result(request_id, result))


def serve(port: int, host_name: str, service_did: str, service_endpoint: str) -> ThreadingHTTPServer:
    authority = f"{host_name}%3A{port}"
    state = State(authority, service_did, service_endpoint)
    handler = type("BoundHandler", (Handler,), {"state": state})
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    print(f"toy DID host on http://{host_name}:{port} (did:wba:{authority})", flush=True)
    print(f"  service did      {service_did}", flush=True)
    print(f"  service endpoint {service_endpoint}", flush=True)
    return server


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    # `create_did_wba_document` 拒收 IP 当主机名（"Hostname cannot be an IP address"），
    # 而 DID 权威段一定是主机名——所以这台主机对外叫 `localhost`，尽管它只绑回环。
    # 这不是将就：真主机（awiki）的权威段也正是 `localhost%3A8765`。
    parser.add_argument("--host-name", default="localhost")
    parser.add_argument("--service-did", required=True)
    parser.add_argument("--service-endpoint", required=True)
    args = parser.parse_args()
    try:
        serve(args.port, args.host_name, args.service_did, args.service_endpoint).serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
