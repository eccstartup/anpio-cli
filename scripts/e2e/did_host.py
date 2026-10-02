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

    def send_json(self, status: int, payload) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
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
