# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import asyncio
import base64
import json
from typing import Any
from urllib.parse import urlencode

from starlette.requests import Request

METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]


def pick(fdp: Any, items: list[Any]) -> Any:
    return items[fdp.ConsumeIntInRange(0, len(items) - 1)]


def text(fdp: Any, max_len: int = 32) -> str:
    return fdp.ConsumeBytes(max_len).decode("utf-8", "ignore")


def token(fdp: Any, max_len: int = 16) -> str:
    raw = fdp.ConsumeBytes(max_len)
    if not raw:
        return "x"
    out = []
    for byte in raw:
        if 48 <= byte <= 57 or 65 <= byte <= 90 or 97 <= byte <= 122:
            out.append(chr(byte))
        elif byte in (45, 95):
            out.append(chr(byte))
        else:
            out.append(chr(97 + (byte % 26)))
    return "".join(out) or "x"


def segment(fdp: Any, max_len: int = 12) -> str:
    value = token(fdp, max_len).strip("-_")
    return value or "x"


def path(fdp: Any, max_segments: int = 3) -> str:
    count = fdp.ConsumeIntInRange(1, max_segments)
    return "/".join(segment(fdp) for _ in range(count))


def scalar_text(fdp: Any) -> str:
    choice = fdp.ConsumeIntInRange(0, 4)
    if choice == 0:
        return str(fdp.ConsumeIntInRange(-1000, 1000))
    if choice == 1:
        return "true" if fdp.ConsumeBool() else "false"
    if choice == 2:
        return text(fdp, 24)
    if choice == 3:
        return str(round(fdp.ConsumeFloatInRange(-1000.0, 1000.0), 3))
    return ""


def query_items(fdp: Any, max_items: int = 4) -> list[tuple[str, str]]:
    items = []
    for _ in range(fdp.ConsumeIntInRange(0, max_items)):
        items.append((segment(fdp, 8), scalar_text(fdp)))
    return items


def headers(
    fdp: Any,
    *,
    include_auth: bool = False,
    include_cookie: bool = False,
) -> dict[str, str]:
    out = {"host": "testserver"}
    if fdp.ConsumeBool():
        out["x-token"] = token(fdp, 20)
    if fdp.ConsumeBool():
        out["x-marker"] = token(fdp, 20)
    if fdp.ConsumeBool():
        out["x-count"] = str(fdp.ConsumeIntInRange(-100, 100))
    if fdp.ConsumeBool():
        out["x-trace-id"] = token(fdp, 20)
    if fdp.ConsumeBool():
        out["accept-encoding"] = "gzip"
    if include_cookie and fdp.ConsumeBool():
        out["cookie"] = f"session={token(fdp, 16)}"
    if include_auth and fdp.ConsumeBool():
        kind = fdp.ConsumeIntInRange(0, 3)
        if kind == 0:
            out["authorization"] = f"Bearer {token(fdp, 32)}"
        elif kind == 1:
            raw = f"{token(fdp, 12)}:{text(fdp, 12)}".encode("ascii", "ignore")
            out["authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
        elif kind == 2:
            out["authorization"] = "Basic " + token(fdp, 24)
        else:
            out["authorization"] = text(fdp, 40)
    for _ in range(fdp.ConsumeIntInRange(0, 2)):
        out[segment(fdp, 8)] = text(fdp, 20)
    return out


def json_value(fdp: Any, depth: int = 0) -> Any:
    top = 5 if depth >= 2 else 7
    kind = fdp.ConsumeIntInRange(0, top)
    if kind == 0:
        return None
    if kind == 1:
        return fdp.ConsumeBool()
    if kind == 2:
        return fdp.ConsumeIntInRange(-1000, 1000)
    if kind == 3:
        return round(fdp.ConsumeFloatInRange(-1000.0, 1000.0), 3)
    if kind == 4:
        return text(fdp, 40)
    if kind == 5:
        return [json_value(fdp, depth + 1) for _ in range(fdp.ConsumeIntInRange(0, 3))]
    if kind == 6:
        out = {}
        for _ in range(fdp.ConsumeIntInRange(0, 3)):
            out[segment(fdp, 8)] = json_value(fdp, depth + 1)
        return out
    return [{"value": json_value(fdp, depth + 1)} for _ in range(fdp.ConsumeIntInRange(0, 2))]


def body_bytes(value: Any) -> bytes:
    try:
        return json.dumps(value).encode("utf-8")
    except Exception:
        return str(value).encode("utf-8", "ignore")


def build_scope(
    method: str,
    path_value: str,
    *,
    headers_map: dict[str, str] | None = None,
    query: list[tuple[str, str]] | None = None,
    scheme: str = "http",
) -> dict[str, Any]:
    raw_headers = []
    for key, value in (headers_map or {}).items():
        raw_headers.append(
            (
                str(key).lower().encode("latin1", "ignore"),
                str(value).encode("latin1", "ignore"),
            )
        )
    query_string = urlencode(query or [], doseq=True).encode()
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": scheme,
        "path": path_value,
        "raw_path": path_value.encode("utf-8", "ignore"),
        "query_string": query_string,
        "headers": raw_headers,
        "client": ("127.0.0.1", 1234),
        "server": ("testserver", 80),
        "state": {},
        "root_path": "",
        "path_params": {},
    }


def build_websocket_scope(
    path_value: str,
    *,
    headers_map: dict[str, str] | None = None,
    query: list[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    raw_headers = []
    for key, value in (headers_map or {}).items():
        raw_headers.append(
            (
                str(key).lower().encode("latin1", "ignore"),
                str(value).encode("latin1", "ignore"),
            )
        )
    return {
        "type": "websocket",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "scheme": "ws",
        "path": path_value,
        "raw_path": path_value.encode("utf-8", "ignore"),
        "query_string": urlencode(query or [], doseq=True).encode(),
        "headers": raw_headers,
        "client": ("127.0.0.1", 1234),
        "server": ("testserver", 80),
        "subprotocols": [],
        "state": {},
        "path_params": {},
    }


def make_receive(body: bytes = b""):
    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return receive


def make_send(messages: list[dict[str, Any]]):
    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    return send


def make_request(
    method: str,
    path_value: str,
    *,
    headers_map: dict[str, str] | None = None,
    query: list[tuple[str, str]] | None = None,
    body: bytes = b"",
) -> Request:
    scope = build_scope(method, path_value, headers_map=headers_map, query=query)
    return Request(scope, receive=make_receive(body))


def run(coro: Any) -> Any:
    return asyncio.run(coro)
