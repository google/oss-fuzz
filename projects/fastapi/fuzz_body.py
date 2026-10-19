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
# - fastapi/params.py
# - fastapi/dependencies/utils.py

import sys

import atheris

with atheris.instrument_imports():
    from fastapi import Body, FastAPI
    from fastapi import routing as fastapi_routing
    from fastapi.dependencies import utils as dep_utils
    from fastapi.exceptions import RequestValidationError, ResponseValidationError
    from fastapi.testclient import TestClient
    from pydantic import BaseModel, ValidationError
    from starlette.exceptions import HTTPException as StarletteHTTPException

    import fastapi_fuzz_utils as fuzz


class Inner(BaseModel):
    name: str
    value: int | None = None


class Payload(BaseModel):
    item: Inner
    tags: list[str] = []
    attrs: dict[str, str | int | bool | None] = {}


class Envelope(BaseModel):
    payload: Payload
    enabled: bool = False


app = FastAPI()


@app.post("/json")
async def json_route(payload: Payload) -> dict[str, object]:
    return payload.model_dump()


@app.post("/embedded")
async def embedded_route(payload: Payload = Body(..., embed=True)) -> dict[str, object]:
    return payload.model_dump()


@app.post("/multi")
async def multi_route(
    primary: Payload = Body(...),
    secondary: Inner = Body(...),
    importance: int = Body(default=0, embed=True),
) -> dict[str, object]:
    return {
        "primary": primary.model_dump(),
        "secondary": secondary.model_dump(),
        "importance": importance,
    }


@app.put("/response", response_model=Envelope)
async def response_route(payload: Envelope) -> Envelope:
    return payload


client = TestClient(app, raise_server_exceptions=False)
routes = {
    route.path: route
    for route in app.routes
    if isinstance(route, fastapi_routing.APIRoute)
}


def valid_inner(fdp: atheris.FuzzedDataProvider) -> dict[str, object]:
    return {
        "name": fuzz.segment(fdp, 16),
        "value": fdp.ConsumeIntInRange(-64, 64),
    }


def valid_payload(fdp: atheris.FuzzedDataProvider) -> dict[str, object]:
    attrs: dict[str, object] = {}
    for _ in range(fdp.ConsumeIntInRange(0, 3)):
        attrs[fuzz.segment(fdp, 8)] = fuzz.json_value(fdp, depth=1)
    return {
        "item": valid_inner(fdp),
        "tags": [fuzz.segment(fdp, 8) for _ in range(fdp.ConsumeIntInRange(0, 3))],
        "attrs": attrs,
    }


def build_body(fdp: atheris.FuzzedDataProvider, path_value: str) -> object:
    if not fdp.ConsumeBool():
        return fuzz.json_value(fdp)
    if path_value == "/json":
        return valid_payload(fdp)
    if path_value == "/embedded":
        return {"payload": valid_payload(fdp)}
    if path_value == "/multi":
        return {
            "primary": valid_payload(fdp),
            "secondary": valid_inner(fdp),
            "importance": fdp.ConsumeIntInRange(-10, 10),
        }
    return {"payload": valid_payload(fdp), "enabled": fdp.ConsumeBool()}


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    path_value = fuzz.pick(fdp, ["/json", "/embedded", "/multi", "/response"])
    body = build_body(fdp, path_value)

    try:
        client.request("POST" if path_value != "/response" else "PUT", path_value, json=body)

        route = routes[path_value]
        flat = dep_utils.get_flat_dependant(route.dependant)
        embed = dep_utils._should_embed_body_fields(flat.body_params)
        dep_utils.get_body_field(flat_dependant=flat, name=route.name, embed_body_fields=embed)
        fuzz.run(
            dep_utils.request_body_to_args(
                body_fields=flat.body_params,
                received_body=body,
                embed_body_fields=embed,
            )
        )
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
