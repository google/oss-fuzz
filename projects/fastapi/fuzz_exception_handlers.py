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

# Targets:
# - fastapi/exception_handlers.py

import sys

import atheris

with atheris.instrument_imports():
    from fastapi import FastAPI, HTTPException
    from fastapi import exception_handlers as fastapi_exception_handlers
    from fastapi import routing as fastapi_routing
    from fastapi.exceptions import RequestValidationError, ResponseValidationError, WebSocketRequestValidationError
    from fastapi.testclient import TestClient
    from fastapi.websockets import WebSocket
    from pydantic import BaseModel, ValidationError
    from starlette.exceptions import HTTPException as StarletteHTTPException

    import fastapi_fuzz_utils as fuzz


class ErrorBody(BaseModel):
    name: str
    size: int


app = FastAPI()


@app.get("/http")
async def http_route(code: int = 400) -> None:
    raise HTTPException(status_code=code, detail={"code": code}, headers={"x-error": "1"})


@app.post("/validate/{item_id}")
async def validate_route(item_id: int, payload: ErrorBody) -> dict[str, object]:
    return {"item_id": item_id, "payload": payload.model_dump()}


@app.get("/response", response_model=ErrorBody)
async def response_route() -> dict[str, object]:
    return {"name": 123, "size": "bad"}


client = TestClient(app, raise_server_exceptions=False)
response_route_obj = next(
    route
    for route in app.routes
    if isinstance(route, fastapi_routing.APIRoute) and route.path == "/response"
)


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    try:
        status_code = fuzz.pick(fdp, [100, 200, 204, 304, 400, 401, 422, 500])
        request = fuzz.make_request(
            "GET",
            "/error",
            headers_map=fuzz.headers(fdp),
            query=fuzz.query_items(fdp),
        )

        http_exc = StarletteHTTPException(
            status_code=status_code,
            detail=fuzz.json_value(fdp),
            headers={"x-error": "1"},
        )
        fuzz.run(fastapi_exception_handlers.http_exception_handler(request, http_exc))

        validation_exc = RequestValidationError(
            [
                {
                    "type": "value_error",
                    "loc": ("body", "payload"),
                    "msg": "bad",
                    "input": fuzz.json_value(fdp),
                }
            ],
            body=fuzz.json_value(fdp),
        )
        fuzz.run(
            fastapi_exception_handlers.request_validation_exception_handler(
                request,
                validation_exc,
            )
        )

        ws_messages: list[dict[str, object]] = []

        async def ws_receive():
            return {"type": "websocket.connect"}

        websocket = WebSocket(
            fuzz.build_websocket_scope("/ws", headers_map=fuzz.headers(fdp)),
            receive=ws_receive,
            send=fuzz.make_send(ws_messages),
        )
        websocket_exc = WebSocketRequestValidationError(
            [
                {
                    "type": "value_error",
                    "loc": ("query", "token"),
                    "msg": "bad",
                    "input": fuzz.text(fdp, 16),
                }
            ]
        )
        fuzz.run(
            fastapi_exception_handlers.websocket_request_validation_exception_handler(
                websocket,
                websocket_exc,
            )
        )

        client.get("/http", params={"code": str(fdp.ConsumeIntInRange(100, 599))})
        client.post(
            f"/validate/{fuzz.segment(fdp) if fdp.ConsumeBool() else fdp.ConsumeIntInRange(-10, 10)}",
            json=fuzz.json_value(fdp),
        )
        client.get("/response")

        response_messages: list[dict[str, object]] = []
        try:
            fuzz.run(
                response_route_obj.app(
                    fuzz.build_scope("GET", "/response", headers_map=fuzz.headers(fdp)),
                    fuzz.make_receive(),
                    fuzz.make_send(response_messages),
                )
            )
        except ResponseValidationError:
            pass
    except (
        ValidationError,
        RequestValidationError,
        ResponseValidationError,
        StarletteHTTPException,
    ):
        return
    except Exception:
        return


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
