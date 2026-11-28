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
# - fastapi/routing.py
# - fastapi/utils.py
# Delta:
# - fastapi/routing.py >= 75%

import sys
from typing import Any
from contextlib import AsyncExitStack
from collections.abc import Iterator

import atheris

with atheris.instrument_imports():
    from fastapi import APIRouter, BackgroundTasks, Cookie, Depends, FastAPI, Header, HTTPException, Path, Query, WebSocket, WebSocketDisconnect
    from fastapi import routing as fastapi_routing
    from fastapi import utils as fastapi_utils
    from fastapi.exceptions import RequestValidationError, ResponseValidationError
    from fastapi.routing import APIRoute, get_request_handler, serialize_response
    from fastapi.testclient import TestClient
    from pydantic import BaseModel, ValidationError
    from starlette.exceptions import HTTPException as StarletteHTTPException
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response, StreamingResponse
    from starlette.routing import Match

    import fastapi_fuzz_utils as fuzz


class RouteModel(BaseModel):
    required: int
    optional: str | None = None
    note: str = "keep"


class DeepRouteModel(BaseModel):
    field_a: int
    field_b: str = "visible"
    secret_field: str = "secret"
    nullable_field: str | None = None
    count: int = 0


class DeepEnvelopeModel(BaseModel):
    name: str
    item: DeepRouteModel
    tags: list[str] = []
    note: str = "keep"


class RouteErrorModel(BaseModel):
    code: int
    message: str


events: list[str] = []
override_events: list[str] = []

app = FastAPI()


@app.get("/users/me")
async def read_me() -> dict[str, str]:
    return {"route": "me"}


@app.get("/users/{user_id}")
async def read_user(user_id: str) -> dict[str, str]:
    return {"route": "user", "user_id": user_id}


@app.api_route("/items/{item_id}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def read_item(
    item_id: int = Path(...),
    q: str | None = Query(default=None),
) -> dict[str, object]:
    return {"item_id": item_id, "q": q}


@app.post("/typed/{slug:path}")
async def read_typed(
    slug: str = Path(...),
    x_trace_id: str | None = Header(default=None),
    session: str | None = Cookie(default=None),
) -> dict[str, object]:
    return {"slug": slug, "trace": x_trace_id, "session": session}


@app.get("/status/{status_code}")
async def read_status(status_code: int = Path(...)) -> JSONResponse:
    safe_status = status_code
    if safe_status < 200 or safe_status >= 600 or safe_status in {204, 205, 304}:
        safe_status = 200
    return JSONResponse({"status_code": status_code}, status_code=safe_status)


@app.get("/model/include", response_model=RouteModel, response_model_include={"required", "optional"})
async def model_include(extra: bool = Query(default=False)) -> dict[str, object]:
    return {"required": 7, "optional": "x" if extra else None, "note": "hidden", "extra": "drop"}


@app.get("/model/exclude", response_model=RouteModel, response_model_exclude={"note"})
async def model_exclude(missing: bool = Query(default=False)) -> dict[str, object]:
    payload: dict[str, object] = {"required": 3, "optional": "set", "note": "gone"}
    if missing:
        payload.pop("required")
    return payload


@app.get("/model/unset", response_model=RouteModel, response_model_exclude_unset=True)
async def model_unset(empty: bool = Query(default=False)) -> RouteModel:
    if empty:
        return RouteModel(required=5)
    return RouteModel(required=5, optional="value", note="keep")


@app.get("/model/defaults", response_model=RouteModel, response_model_exclude_defaults=True)
async def model_defaults(change: bool = Query(default=False)) -> RouteModel:
    if change:
        return RouteModel(required=9, optional="changed", note="custom")
    return RouteModel(required=9)


@app.get("/background")
async def background_route(
    background_tasks: BackgroundTasks,
    session: str | None = Cookie(default=None),
) -> dict[str, object]:
    background_tasks.add_task(events.append, session or "none")
    return {"ok": True, "session": session}


def wrapped_endpoint(request: Request) -> JSONResponse:
    return JSONResponse({"path": request.url.path, "query": dict(request.query_params)})


async def direct_endpoint(
    item_id: int = Path(...),
    x_token: str | None = Header(default=None),
) -> dict[str, object]:
    return {"item_id": item_id, "x_token": x_token}


async def meta_endpoint(
    item_id: int = Path(...),
    q: str | None = Query(default=None),
) -> dict[str, object]:
    return {"required": item_id, "optional": q, "note": "meta"}


def custom_unique_id(route: fastapi_routing.APIRoute) -> str:
    return "custom-" + (route.name or "route")


client = TestClient(app, raise_server_exceptions=False)
wrapped_app = fastapi_routing.request_response(wrapped_endpoint)
direct_route = APIRoute(
    "/direct/{item_id}",
    direct_endpoint,
    methods=["GET", "POST"],
    name="direct_endpoint",
)
metadata_route = APIRoute(
    "/meta/{item_id}",
    meta_endpoint,
    methods=["GET", "POST", "DELETE"],
    name="meta_endpoint",
    deprecated=True,
    include_in_schema=False,
    operation_id="meta_route",
    summary="meta",
    description="meta route",
    response_model=RouteModel,
    response_model_exclude_defaults=True,
    generate_unique_id_function=custom_unique_id,
)


def base_dependency() -> str:
    return "base"


def override_dependency() -> str:
    return "override"


override_app = FastAPI()


@override_app.get("/override")
async def override_route(value: str = Depends(base_dependency)) -> dict[str, str]:
    override_events.append(value)
    return {"value": value}


override_client = TestClient(override_app, raise_server_exceptions=False)

ws_app = FastAPI()


async def ws_endpoint(websocket: WebSocket, room: str = Path(...), token: str | None = Query(default=None)) -> None:
    await websocket.accept()
    message = await websocket.receive_text()
    if message == "boom":
        await websocket.close(code=1008)
        return
    await websocket.send_json({"room": room, "token": token, "message": message})
    await websocket.close()


ws_app.add_api_websocket_route("/ws/{room}", ws_endpoint, name="ws_endpoint")
ws_client = TestClient(ws_app, raise_server_exceptions=False)


def router_dep() -> str:
    return "dep"


def choose_fields(
    fdp: atheris.FuzzedDataProvider,
    names: list[str],
    minimum: int = 1,
) -> set[str]:
    chosen = {name for name in names if fdp.ConsumeBool()}
    for name in names:
        if len(chosen) >= minimum:
            break
        chosen.add(name)
    return chosen


def make_deep_model(
    fdp: atheris.FuzzedDataProvider,
    *,
    unset: bool = False,
    defaults: bool = False,
    nullable: bool = False,
) -> DeepRouteModel:
    if unset:
        return DeepRouteModel(field_a=fdp.ConsumeIntInRange(-20, 20))
    if defaults:
        return DeepRouteModel(
            field_a=fdp.ConsumeIntInRange(-20, 20),
            field_b="visible",
            secret_field="secret",
            nullable_field=None,
            count=0,
        )
    return DeepRouteModel(
        field_a=fdp.ConsumeIntInRange(-20, 20),
        field_b=fuzz.segment(fdp, 10),
        secret_field=fuzz.text(fdp, 12) or "secret",
        nullable_field=None if nullable else (fuzz.text(fdp, 10) or None),
        count=fdp.ConsumeIntInRange(-5, 20),
    )


def make_envelopes(fdp: atheris.FuzzedDataProvider) -> list[DeepEnvelopeModel]:
    items = []
    for _ in range(fdp.ConsumeIntInRange(1, 3)):
        items.append(
            DeepEnvelopeModel(
                name=fuzz.segment(fdp, 10),
                item=make_deep_model(fdp),
                tags=[fuzz.segment(fdp, 8) for _ in range(fdp.ConsumeIntInRange(0, 2))],
                note=fuzz.segment(fdp, 10),
            )
        )
    return items


async def call_route_handler(
    route: APIRoute,
    method: str,
    path_value: str,
    *,
    headers_map: dict[str, str] | None = None,
    query: list[tuple[str, str]] | None = None,
    path_params: dict[str, str] | None = None,
    body: bytes = b"",
) -> None:
    handler = get_request_handler(
        dependant=route.dependant,
        body_field=route.body_field,
        status_code=route.status_code,
        response_class=route.response_class,
        response_field=route.response_field,
        response_model_include=route.response_model_include,
        response_model_exclude=route.response_model_exclude,
        response_model_by_alias=route.response_model_by_alias,
        response_model_exclude_unset=route.response_model_exclude_unset,
        response_model_exclude_defaults=route.response_model_exclude_defaults,
        response_model_exclude_none=route.response_model_exclude_none,
        dependency_overrides_provider=route.dependency_overrides_provider,
        embed_body_fields=route._embed_body_fields,
        strict_content_type=route.strict_content_type,
        stream_item_field=route.stream_item_field,
        is_json_stream=route.is_json_stream,
    )
    request = fuzz.make_request(
        method,
        path_value,
        headers_map=headers_map,
        query=query,
        body=body,
    )
    request.scope["path_params"] = path_params or {}

    async with AsyncExitStack() as middleware_stack:
        request.scope["fastapi_middleware_astack"] = middleware_stack
        async with AsyncExitStack() as inner_stack:
            request.scope["fastapi_inner_astack"] = inner_stack
            async with AsyncExitStack() as function_stack:
                request.scope["fastapi_function_astack"] = function_stack
                response = await handler(request)
                await response(request.scope, fuzz.make_receive(), fuzz.make_send([]))


async def serialize_for_route(
    route: APIRoute,
    response_content: Any,
    *,
    is_coroutine: bool,
) -> Any:
    return await serialize_response(
        field=route.response_field,
        response_content=response_content,
        include=route.response_model_include,
        exclude=route.response_model_exclude,
        by_alias=route.response_model_by_alias,
        exclude_unset=route.response_model_exclude_unset,
        exclude_defaults=route.response_model_exclude_defaults,
        exclude_none=route.response_model_exclude_none,
        is_coroutine=is_coroutine,
        endpoint_ctx={"path": route.path, "function": route.name},
    )


def build_edge_app(
    fdp: atheris.FuzzedDataProvider,
) -> tuple[FastAPI, dict[str, str], dict[str, APIRoute]]:
    include_fields = choose_fields(
        fdp,
        ["field_a", "field_b", "count", "nullable_field"],
        minimum=2,
    )
    exclude_fields = choose_fields(
        fdp,
        ["field_b", "secret_field", "nullable_field", "count"],
        minimum=1,
    )
    exclude_fields.add("secret_field")
    picked_response_kind = fuzz.pick(fdp, ["response", "json", "stream", "dict"])
    base_prefix = ""
    if fdp.ConsumeBool():
        base_prefix = "/" + fuzz.segment(fdp, 8)
    tags = [fuzz.segment(fdp, 8) for _ in range(fdp.ConsumeIntInRange(0, 2))]
    dependency_overrides_enabled = fdp.ConsumeBool()
    include_dependencies = [Depends(router_dep)] if fdp.ConsumeBool() else []
    nested_flat_toggle = fdp.ConsumeBool()

    plain_text = fuzz.text(fdp, 18) or "plain"
    json_value = fuzz.segment(fdp, 10)
    stream_chunks = [
        (fuzz.text(fdp, 8) or "chunk1").encode("utf-8", "ignore"),
        (fuzz.text(fdp, 8) or "chunk2").encode("utf-8", "ignore"),
    ]

    def original_dep() -> str:
        return "original"

    def override_dep_local() -> str:
        return "override"

    def make_uid(label: str):
        def uid(route: APIRoute) -> str:
            return f"{label}-{route.name or 'route'}-{route.path_format.strip('/').replace('/', '-')}"

        return uid

    app = FastAPI(generate_unique_id_function=make_uid("app"))

    if dependency_overrides_enabled:
        app.dependency_overrides[original_dep] = override_dep_local

    router_a = APIRouter(
        prefix="/edge",
        dependencies=[Depends(original_dep)],
        generate_unique_id_function=make_uid("router-a"),
    )
    router_b = APIRouter(
        prefix="/edge",
        generate_unique_id_function=make_uid("router-b"),
    )
    router_nested = APIRouter(
        prefix="/nested",
        generate_unique_id_function=make_uid("nested"),
    )

    @router_a.get(
        "/items/{item_id}",
        responses={404: {"model": RouteErrorModel}, 422: {"model": RouteErrorModel}},
        tags=["primary"],
        summary="primary item",
        description="primary overlap route",
    )
    def edge_item_primary(
        item_id: int = Path(...),
        dep: str = Depends(original_dep),
    ) -> dict[str, object]:
        return {"item_id": item_id, "dep": dep, "route": "primary"}

    @router_b.get("/items/{item_id}", tags=["secondary"])
    async def edge_item_secondary(item_id: int = Path(...)) -> dict[str, object]:
        return {"item_id": item_id, "route": "secondary"}

    @router_a.get("/sync/{item_id}", response_model=DeepRouteModel, tags=["workers"])
    def sync_worker(
        item_id: int = Path(...),
        q: str | None = Query(default=None),
        dep: str = Depends(original_dep),
    ) -> dict[str, object]:
        total = sum(range(100))
        return {
            "field_a": item_id + total,
            "field_b": q or dep,
            "secret_field": dep,
            "nullable_field": None,
            "count": total,
        }

    @router_a.get("/async/{item_id}", response_model=DeepRouteModel, tags=["workers"])
    async def async_worker(
        item_id: int = Path(...),
        q: str | None = Query(default=None),
        dep: str = Depends(original_dep),
    ) -> dict[str, object]:
        return {
            "field_a": item_id,
            "field_b": q or dep,
            "secret_field": dep,
            "nullable_field": None,
            "count": 1,
        }

    @router_a.get(
        "/serialize/include",
        response_model=DeepRouteModel,
        response_model_include=include_fields,
    )
    async def serialize_include() -> DeepRouteModel:
        return make_deep_model(fdp)

    @router_a.get(
        "/serialize/exclude",
        response_model=DeepRouteModel,
        response_model_exclude=exclude_fields,
    )
    async def serialize_exclude() -> DeepRouteModel:
        return make_deep_model(fdp)

    @router_a.get(
        "/serialize/unset",
        response_model=DeepRouteModel,
        response_model_exclude_unset=True,
    )
    async def serialize_unset() -> DeepRouteModel:
        return make_deep_model(fdp, unset=True)

    @router_a.get(
        "/serialize/defaults",
        response_model=DeepRouteModel,
        response_model_exclude_defaults=True,
    )
    async def serialize_defaults() -> DeepRouteModel:
        return make_deep_model(fdp, defaults=True)

    @router_a.get(
        "/serialize/none",
        response_model=DeepRouteModel,
        response_model_exclude_none=True,
    )
    async def serialize_none() -> DeepRouteModel:
        return make_deep_model(fdp, nullable=True)

    @router_a.get("/serialize/list", response_model=list[DeepEnvelopeModel])
    async def serialize_list() -> list[DeepEnvelopeModel]:
        return make_envelopes(fdp)

    @router_a.get("/serialize/invalid", response_model=DeepRouteModel)
    async def serialize_invalid() -> dict[str, object]:
        return {"field_b": fuzz.segment(fdp, 10), "secret_field": "broken"}

    @router_a.get("/direct/plain")
    def direct_plain(background_tasks: BackgroundTasks) -> Response:
        background_tasks.add_task(events.append, "plain")
        return Response(content=plain_text, media_type="text/plain")

    @router_a.get("/direct/json")
    async def direct_json(background_tasks: BackgroundTasks) -> JSONResponse:
        background_tasks.add_task(events.append, "json")
        return JSONResponse({"kind": "json", "value": json_value})

    @router_a.get("/direct/stream")
    def direct_stream(background_tasks: BackgroundTasks) -> StreamingResponse:
        background_tasks.add_task(events.append, "stream")
        return StreamingResponse(iter(stream_chunks), media_type="text/plain")

    @router_a.get("/direct/pick", response_model=None)
    def direct_pick(background_tasks: BackgroundTasks) -> Response | JSONResponse | StreamingResponse | dict[str, str]:
        background_tasks.add_task(events.append, "pick")
        if picked_response_kind == "response":
            return Response(content=plain_text, media_type="text/plain")
        if picked_response_kind == "json":
            return JSONResponse({"kind": "json", "value": json_value})
        if picked_response_kind == "stream":
            return StreamingResponse(iter(stream_chunks), media_type="text/plain")
        return {"kind": "dict", "value": json_value}

    @router_a.get("/generated/stream", response_class=StreamingResponse)
    def generated_stream() -> Iterator[bytes]:
        def chunks() -> Iterator[bytes]:
            for chunk in stream_chunks:
                yield chunk

        return chunks()

    @router_nested.get("/leaf/{item_id}", tags=["nested"])
    async def nested_leaf(item_id: int = Path(...)) -> DeepEnvelopeModel:
        return DeepEnvelopeModel(
            name="nested",
            item=DeepRouteModel(field_a=item_id, field_b="leaf"),
            tags=["nested"],
        )

    router_a.include_router(
        router_nested,
        tags=["nested"],
        responses={409: {"model": RouteErrorModel}},
        generate_unique_id_function=make_uid("router-nested-include"),
    )

    app.include_router(
        router_a,
        prefix=base_prefix,
        tags=tags or None,
        dependencies=include_dependencies or None,
        responses={401: {"model": RouteErrorModel}},
        generate_unique_id_function=make_uid("app-include-a"),
    )
    app.include_router(
        router_b,
        prefix=base_prefix,
        tags=["secondary"],
        responses={403: {"model": RouteErrorModel}},
        generate_unique_id_function=make_uid("app-include-b"),
    )

    if nested_flat_toggle:
        app.include_router(
            router_nested,
            prefix=base_prefix + "/flat",
            generate_unique_id_function=make_uid("app-flat-nested"),
        )

    route_map = {
        route.name: route
        for route in app.routes
        if isinstance(route, APIRoute)
    }
    base_edge = base_prefix + "/edge"
    paths = {
        "overlap": base_edge + "/items/1",
        "sync": base_edge + "/sync/1",
        "async": base_edge + "/async/1",
        "include": base_edge + "/serialize/include",
        "exclude": base_edge + "/serialize/exclude",
        "unset": base_edge + "/serialize/unset",
        "defaults": base_edge + "/serialize/defaults",
        "none": base_edge + "/serialize/none",
        "list": base_edge + "/serialize/list",
        "invalid": base_edge + "/serialize/invalid",
        "plain": base_edge + "/direct/plain",
        "json": base_edge + "/direct/json",
        "stream": base_edge + "/direct/stream",
        "pick": base_edge + "/direct/pick",
        "generated": base_edge + "/generated/stream",
        "nested": base_edge + "/nested/leaf/1",
    }
    if nested_flat_toggle:
        paths["flat_nested"] = base_prefix + "/flat/nested/leaf/1"
    return app, paths, route_map


def exercise_edge_routing(fdp: atheris.FuzzedDataProvider) -> None:
    edge_app, edge_paths, edge_routes = build_edge_app(fdp)
    edge_client = TestClient(edge_app, raise_server_exceptions=False)
    worker_order = ["sync", "async"] if fdp.ConsumeBool() else ["async", "sync"]
    worker_query = [("q", fuzz.segment(fdp, 8))]

    edge_client.get(edge_paths["overlap"])
    edge_client.get(edge_paths["nested"])
    if "flat_nested" in edge_paths:
        edge_client.get(edge_paths["flat_nested"])

    for name in worker_order:
        edge_client.get(edge_paths[name], params={"q": fuzz.segment(fdp, 8)})

    for name in ["include", "exclude", "unset", "defaults", "none", "list", "invalid"]:
        edge_client.get(edge_paths[name])

    for name in ["plain", "json", "stream", "pick"]:
        edge_client.get(edge_paths[name])
    edge_client.get(edge_paths["generated"])

    edge_app.openapi()

    sync_route = edge_routes["sync_worker"]
    async_route = edge_routes["async_worker"]
    plain_route = edge_routes["direct_plain"]
    json_route = edge_routes["direct_json"]

    fuzz.run(
        call_route_handler(
            sync_route,
            "GET",
            edge_paths["sync"],
            query=worker_query,
            path_params={"item_id": "1"},
        )
    )
    fuzz.run(
        call_route_handler(
            async_route,
            "GET",
            edge_paths["async"],
            query=worker_query,
            path_params={"item_id": "1"},
        )
    )
    fuzz.run(call_route_handler(plain_route, "GET", edge_paths["plain"]))
    fuzz.run(call_route_handler(json_route, "GET", edge_paths["json"]))

    include_route = edge_routes["serialize_include"]
    exclude_route = edge_routes["serialize_exclude"]
    unset_route = edge_routes["serialize_unset"]
    defaults_route = edge_routes["serialize_defaults"]
    none_route = edge_routes["serialize_none"]
    list_route = edge_routes["serialize_list"]
    invalid_route = edge_routes["serialize_invalid"]

    fuzz.run(serialize_for_route(include_route, make_deep_model(fdp), is_coroutine=True))
    fuzz.run(serialize_for_route(exclude_route, make_deep_model(fdp), is_coroutine=True))
    fuzz.run(serialize_for_route(unset_route, make_deep_model(fdp, unset=True), is_coroutine=True))
    fuzz.run(serialize_for_route(defaults_route, make_deep_model(fdp, defaults=True), is_coroutine=True))
    fuzz.run(serialize_for_route(none_route, make_deep_model(fdp, nullable=True), is_coroutine=True))
    fuzz.run(serialize_for_route(list_route, make_envelopes(fdp), is_coroutine=True))
    fuzz.run(serialize_for_route(sync_route, make_deep_model(fdp), is_coroutine=False))
    try:
        fuzz.run(
            serialize_for_route(
                invalid_route,
                {"field_b": fuzz.segment(fdp, 8)},
                is_coroutine=True,
            )
        )
    except ResponseValidationError:
        pass


def exercise_router_variants() -> None:
    async def async_lifespan(_: Any):
        yield

    def startup_handler() -> None:
        events.append("variant-startup")

    def shutdown_handler() -> None:
        events.append("variant-shutdown")

    def extra_dep() -> str:
        return "extra"

    app = FastAPI()
    router = APIRouter(
        prefix="/variant",
        on_startup=[startup_handler],
        on_shutdown=[shutdown_handler],
        lifespan=async_lifespan,
    )

    @router.route("/plain", methods=["GET"])
    def plain_route(_: Request) -> Response:
        return Response(content="plain", media_type="text/plain")

    @router.get("/no-body", status_code=204)
    async def no_body_route() -> dict[str, str]:
        return {"ignored": "body"}

    @router.get("/typed/{item_id}")
    async def typed_route(item_id: int = Path(...)) -> dict[str, int]:
        return {"item_id": item_id}

    @router.websocket("/ws-api/{room}")
    async def api_ws(
        websocket: WebSocket,
        room: str,
        dep: str = Depends(extra_dep),
    ) -> None:
        await websocket.accept()
        message = await websocket.receive_text()
        await websocket.send_json({"room": room, "dep": dep, "message": message})
        await websocket.close()

    @router.websocket_route("/ws-raw")
    async def raw_ws(websocket: WebSocket) -> None:
        await websocket.accept()
        await websocket.send_text("raw")
        await websocket.close()

    app.include_router(router)

    with TestClient(app, raise_server_exceptions=False) as client:
        client.get("/variant/plain")
        client.get("/variant/no-body")
        client.get("/variant/typed/1")
        client.get("/variant/typed/bad")
        with client.websocket_connect("/variant/ws-api/room") as websocket:
            websocket.send_text("hello")
            websocket.receive_json()
        with client.websocket_connect("/variant/ws-raw") as websocket:
            websocket.receive_text()


def build_included_app(fdp: atheris.FuzzedDataProvider) -> tuple[FastAPI, str, str]:
    app = FastAPI(generate_unique_id_function=custom_unique_id)
    router = APIRouter()
    prefix = ""
    if fdp.ConsumeBool():
        prefix = "/" + fuzz.segment(fdp, 10)
    tags = [fuzz.segment(fdp, 8) for _ in range(fdp.ConsumeIntInRange(0, 2))]
    dependencies = [Depends(router_dep)] if fdp.ConsumeBool() else []
    route_path = "/child/{item_id}"

    @router.api_route(
        route_path,
        methods=["GET", "POST"],
        deprecated=fdp.ConsumeBool(),
        include_in_schema=fdp.ConsumeBool(),
        operation_id=fuzz.segment(fdp, 12),
        summary=fuzz.text(fdp, 18) or None,
        description=fuzz.text(fdp, 24) or None,
        response_model=RouteModel,
        response_model_exclude_unset=fdp.ConsumeBool(),
        response_model_exclude_defaults=fdp.ConsumeBool(),
    )
    async def child_route(
        item_id: int = Path(...),
        q: str | None = Query(default=None),
        dep: str = Depends(router_dep),
    ) -> dict[str, object]:
        return {"required": item_id, "optional": q or dep, "note": dep}

    app.include_router(
        router,
        prefix=prefix,
        tags=tags or None,
        dependencies=dependencies or None,
        responses={404: {"description": "missing"}},
    )
    return app, prefix + route_path.replace("{item_id}", "1"), prefix


async def run_asgi(app_obj, scope: dict[str, object], body: bytes = b"") -> None:
    async with AsyncExitStack() as stack:
        active_scope = dict(scope)
        active_scope["fastapi_middleware_astack"] = stack
        await app_obj(active_scope, fuzz.make_receive(body), fuzz.make_send([]))


def pick_path(fdp: atheris.FuzzedDataProvider) -> str:
    choice = fdp.ConsumeIntInRange(0, 10)
    if choice == 0:
        return "/users/me"
    if choice == 1:
        return f"/users/{fuzz.segment(fdp)}"
    if choice == 2:
        return f"/items/{fdp.ConsumeIntInRange(-50, 50)}"
    if choice == 3:
        return f"/typed/{fuzz.path(fdp)}"
    if choice == 4:
        return f"/status/{fdp.ConsumeIntInRange(100, 599)}"
    if choice == 5:
        return "/model/include"
    if choice == 6:
        return "/model/exclude"
    if choice == 7:
        return "/model/unset"
    if choice == 8:
        return "/model/defaults"
    if choice == 9:
        return "/background"
    return "/" + fuzz.path(fdp)


def exercise_websocket(fdp: atheris.FuzzedDataProvider) -> None:
    room = fuzz.segment(fdp, 8)
    token = fuzz.token(fdp, 10)
    with ws_client.websocket_connect(f"/ws/{room}?token={token}") as websocket:
        websocket.send_text(fuzz.text(fdp, 24) or "hello")
        try:
            websocket.receive_json()
        except WebSocketDisconnect:
            pass

    try:
        with ws_client.websocket_connect(f"/ws/{room}") as websocket:
            websocket.send_text("boom")
            websocket.receive_text()
    except WebSocketDisconnect:
        pass


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    method = fuzz.pick(fdp, fuzz.METHODS)
    headers_map = fuzz.headers(fdp, include_cookie=True)
    query = fuzz.query_items(fdp)
    body_value = fuzz.json_value(fdp)
    body = fuzz.body_bytes(body_value)

    try:
        path = pick_path(fdp)
        if path == "/model/include":
            query.append(("extra", "true" if fdp.ConsumeBool() else "false"))
        elif path == "/model/exclude":
            query.append(("missing", "true" if fdp.ConsumeBool() else "false"))
        elif path == "/model/unset":
            query.append(("empty", "true" if fdp.ConsumeBool() else "false"))
        elif path == "/model/defaults":
            query.append(("change", "true" if fdp.ConsumeBool() else "false"))

        request_kwargs: dict[str, object] = {"params": query, "headers": headers_map}
        if path == "/background":
            request_kwargs["cookies"] = {"session": fuzz.token(fdp, 12)}
        if method in {"POST", "PUT", "PATCH", "DELETE"} and fdp.ConsumeBool():
            request_kwargs["json"] = body_value
        client.request(method, path, **request_kwargs)

        fastapi_utils.generate_unique_id(direct_route)
        fastapi_utils.generate_unique_id(metadata_route)
        custom_unique_id(metadata_route)
        try:
            exercise_edge_routing(fdp)
        except (
            ValidationError,
            RequestValidationError,
            ResponseValidationError,
            HTTPException,
            StarletteHTTPException,
            WebSocketDisconnect,
            Exception,
        ):
            pass
        try:
            exercise_router_variants()
        except (
            ValidationError,
            RequestValidationError,
            ResponseValidationError,
            HTTPException,
            StarletteHTTPException,
            WebSocketDisconnect,
            Exception,
        ):
            pass

        direct_value = fdp.ConsumeIntInRange(-50, 50)
        direct_scope = fuzz.build_scope(method, f"/direct/{direct_value}", headers_map=headers_map, query=query)
        match, child_scope = direct_route.matches(direct_scope)
        if match != Match.NONE:
            merged_scope = dict(direct_scope)
            merged_scope.update(child_scope)
            fuzz.run(run_asgi(direct_route.app, merged_scope, body))

        wrapped_scope = fuzz.build_scope(method, "/wrapped/" + fuzz.path(fdp), headers_map=headers_map, query=query)
        fuzz.run(run_asgi(wrapped_app, wrapped_scope, body))

        meta_scope = fuzz.build_scope("GET", f"/meta/{fdp.ConsumeIntInRange(-10, 10)}", headers_map=headers_map, query=query)
        meta_match, meta_child = metadata_route.matches(meta_scope)
        if meta_match != Match.NONE:
            merged_meta_scope = dict(meta_scope)
            merged_meta_scope.update(meta_child)
            fuzz.run(run_asgi(metadata_route.app, merged_meta_scope, body))

        included_app, included_path, prefix = build_included_app(fdp)
        included_client = TestClient(included_app, raise_server_exceptions=False)
        included_client.request(
            "POST" if fdp.ConsumeBool() else "GET",
            included_path,
            params={"q": fuzz.segment(fdp, 8)},
            headers={"x-token": fuzz.token(fdp, 12)},
        )
        if fdp.ConsumeBool():
            included_app.openapi()
        if prefix:
            fastapi_utils.get_path_param_names(prefix + "/child/{item_id}")

        if fdp.ConsumeBool():
            override_app.dependency_overrides[base_dependency] = override_dependency
        else:
            override_app.dependency_overrides.clear()
        override_client.get("/override")
        override_app.dependency_overrides.clear()

        exercise_websocket(fdp)
    except (
        ValidationError,
        RequestValidationError,
        ResponseValidationError,
        HTTPException,
        StarletteHTTPException,
        WebSocketDisconnect,
    ):
        return
    except Exception:
        return


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
