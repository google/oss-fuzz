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
# - fastapi/dependencies/utils.py
# - fastapi/background.py
# Delta:
# - fastapi/dependencies/utils.py >= 75%

import inspect
import sys
from contextlib import AsyncExitStack

import atheris

with atheris.instrument_imports():
    from fastapi import BackgroundTasks, Body, Cookie, Depends, FastAPI, Header, HTTPException, Path, Query, Request, Response, Security
    from fastapi import routing as fastapi_routing
    from fastapi.dependencies import utils as dep_utils
    from fastapi.exceptions import RequestValidationError, ResponseValidationError
    from fastapi.security import OAuth2PasswordBearer, SecurityScopes
    from fastapi.testclient import TestClient
    from pydantic import BaseModel, ValidationError
    from starlette.exceptions import HTTPException as StarletteHTTPException

    import fastapi_fuzz_utils as fuzz


class DepPayload(BaseModel):
    name: str
    amount: int


events: list[str] = []
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/token",
    scopes={"read": "Read access", "write": "Write access"},
    auto_error=False,
)


def parameterless_dep() -> int:
    return 7


def sync_yield_dep(limit: int = Query(default=0, ge=0, le=100)):
    events.append(f"sync-enter:{limit}")
    try:
        yield limit
    finally:
        events.append(f"sync-exit:{limit}")


async def async_yield_dep(x_marker: str | None = Header(default=None, alias="x-marker")):
    marker = x_marker or "marker"
    events.append(f"async-enter:{marker}")
    try:
        yield marker
    finally:
        events.append(f"async-exit:{marker}")


def count_dep(limit: int = Query(default=0, ge=0, le=100)) -> int:
    return limit


def dep_a(flag: bool = Query(default=False), label: str = Query(default="a")) -> str:
    if flag:
        raise HTTPException(status_code=418, detail="dep-a")
    return label


def dep_b(value: str = Depends(dep_a)) -> str:
    return value.upper()


async def dep_c(value: str = Depends(dep_b)) -> dict[str, str]:
    return {"value": value}


async def scoped_dep(
    security_scopes: SecurityScopes,
    token: str | None = Security(oauth2_scheme, scopes=["read"]),
) -> dict[str, object]:
    return {"token": token, "scopes": list(security_scopes.scopes)}


async def state_dep(
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    token: str | None = Security(oauth2_scheme, scopes=["read"]),
    marker: str = Depends(async_yield_dep, scope="function"),
    sync_limit: int = Depends(sync_yield_dep, scope="request"),
    limit: int = Depends(count_dep),
) -> dict[str, object]:
    background_tasks.add_task(events.append, f"task:{marker}")
    response.headers["x-limit"] = str(limit)
    return {
        "path": request.url.path,
        "token": token,
        "marker": marker,
        "sync_limit": sync_limit,
        "limit": limit,
    }


async def dependency_endpoint(
    item_id: int = Path(..., ge=-10, le=10),
    payload: DepPayload = Body(...),
    flag: bool = Body(default=False, embed=True),
    session: str | None = Cookie(default=None, alias="session"),
    state: dict[str, object] = Depends(state_dep),
) -> dict[str, object]:
    return {
        "item_id": item_id,
        "payload": payload.model_dump(),
        "flag": flag,
        "session": session,
        "state": state,
    }


async def dependency_error_endpoint(
    item_id: int = Path(..., ge=-10, le=10),
    payload: DepPayload = Body(...),
    state: dict[str, object] = Depends(state_dep),
) -> dict[str, object]:
    raise HTTPException(status_code=409, detail={"item_id": item_id, "state": state, "payload": payload.model_dump()})


async def nested_endpoint(value: dict[str, str] = Depends(dep_c)) -> dict[str, str]:
    return value


async def scoped_endpoint(state: dict[str, object] = Depends(scoped_dep)) -> dict[str, object]:
    return state


app = FastAPI()
app.post("/deps/{item_id}")(dependency_endpoint)
app.post("/deps-error/{item_id}")(dependency_error_endpoint)
app.get("/nested")(nested_endpoint)
app.get("/scoped")(scoped_endpoint)
client = TestClient(app, raise_server_exceptions=False)

main_dependant = dep_utils.get_dependant(path="/deps/{item_id}", call=dependency_endpoint)
main_flat = dep_utils.get_flat_dependant(main_dependant)
main_embed = dep_utils._should_embed_body_fields(main_flat.body_params)
error_dependant = dep_utils.get_dependant(path="/deps-error/{item_id}", call=dependency_error_endpoint)
error_flat = dep_utils.get_flat_dependant(error_dependant)
error_embed = dep_utils._should_embed_body_fields(error_flat.body_params)
nested_dependant = dep_utils.get_dependant(path="/nested", call=nested_endpoint)
nested_flat = dep_utils.get_flat_dependant(nested_dependant)
scoped_dependant = dep_utils.get_dependant(path="/scoped", call=scoped_endpoint)
scoped_flat = dep_utils.get_flat_dependant(scoped_dependant)

override_provider = type(
    "OverrideProvider",
    (),
    {"dependency_overrides": {count_dep: parameterless_dep}},
)()

main_route = next(
    route
    for route in app.routes
    if isinstance(route, fastapi_routing.APIRoute) and route.path == "/deps/{item_id}"
)
scoped_route = next(
    route
    for route in app.routes
    if isinstance(route, fastapi_routing.APIRoute) and route.path == "/scoped"
)


async def solve_once(
    request: Request,
    body: object,
    dependant,
    embed_body_fields: bool,
    use_override: bool,
) -> None:
    async with AsyncExitStack() as request_stack:
        request.scope["fastapi_inner_astack"] = request_stack
        async with AsyncExitStack() as function_stack:
            request.scope["fastapi_function_astack"] = function_stack
            result = await dep_utils.solve_dependencies(
                request=request,
                dependant=dependant,
                body=body,
                dependency_overrides_provider=override_provider if use_override else None,
                dependency_cache={},
                async_exit_stack=request_stack,
                embed_body_fields=embed_body_fields,
            )
            if result.background_tasks is not None:
                await result.background_tasks()
            if not result.errors and dependant.call is not None:
                value = dependant.call(**result.values)
                if inspect.isawaitable(value):
                    await value


def build_body(fdp: atheris.FuzzedDataProvider) -> object:
    if not fdp.ConsumeBool():
        return fuzz.json_value(fdp)
    return {
        "payload": {
            "name": fuzz.segment(fdp, 16),
            "amount": fdp.ConsumeIntInRange(-50, 200),
        },
        "flag": fdp.ConsumeBool(),
    }


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    events.clear()

    try:
        dep_utils.get_parameterless_sub_dependant(depends=Depends(parameterless_dep), path="/deps/{item_id}")
        dep_utils.get_body_field(flat_dependant=main_flat, name=main_route.name, embed_body_fields=main_embed)
        dep_utils.get_body_field(flat_dependant=error_flat, name="dependency_error_endpoint", embed_body_fields=error_embed)
        dep_utils.get_body_field(flat_dependant=scoped_flat, name=scoped_route.name, embed_body_fields=False)
        dep_utils.get_flat_dependant(main_dependant, skip_repeats=fdp.ConsumeBool())
        dep_utils.get_flat_dependant(nested_dependant, skip_repeats=fdp.ConsumeBool())
        dep_utils.get_flat_dependant(scoped_dependant, skip_repeats=fdp.ConsumeBool())

        item_id: str | int
        if fdp.ConsumeBool():
            item_id = fdp.ConsumeIntInRange(-20, 20)
        else:
            item_id = fuzz.segment(fdp)

        body = build_body(fdp)
        headers_map = fuzz.headers(fdp, include_auth=True, include_cookie=True)
        headers_map["x-marker"] = fuzz.token(fdp, 16)
        session_value = fuzz.token(fdp, 16)
        headers_map["cookie"] = f"session={session_value}"
        query = [("limit", str(fdp.ConsumeIntInRange(-20, 120)))]

        request_kwargs: dict[str, object] = {
            "json": body,
            "headers": headers_map,
            "params": query,
            "cookies": {"session": session_value},
        }

        client.post(f"/deps/{item_id}", **request_kwargs)
        client.post(f"/deps-error/{item_id}", **request_kwargs)
        client.get(
            "/nested",
            params={
                "flag": "true" if fdp.ConsumeBool() else "false",
                "label": fuzz.segment(fdp, 12),
            },
        )
        client.get("/scoped", headers={"authorization": "Bearer " + fuzz.token(fdp, 20)})

        request = fuzz.make_request(
            "POST",
            f"/deps/{item_id}",
            headers_map=headers_map,
            query=query,
            body=fuzz.body_bytes(body),
        )
        request.scope["path_params"] = {"item_id": str(item_id)}
        fuzz.run(solve_once(request, body, main_dependant, main_embed, use_override=fdp.ConsumeBool()))

        error_request = fuzz.make_request(
            "POST",
            f"/deps-error/{item_id}",
            headers_map=headers_map,
            query=query,
            body=fuzz.body_bytes(body),
        )
        error_request.scope["path_params"] = {"item_id": str(item_id)}
        try:
            fuzz.run(solve_once(error_request, body, error_dependant, error_embed, use_override=False))
        except HTTPException:
            pass

        nested_request = fuzz.make_request(
            "GET",
            "/nested",
            query=[
                ("flag", "true" if fdp.ConsumeBool() else "false"),
                ("label", fuzz.segment(fdp, 12)),
            ],
        )
        fuzz.run(solve_once(nested_request, None, nested_dependant, False, use_override=False))

        scoped_request = fuzz.make_request(
            "GET",
            "/scoped",
            headers_map={"authorization": "Bearer " + fuzz.token(fdp, 16)},
        )
        fuzz.run(solve_once(scoped_request, None, scoped_dependant, False, use_override=False))
    except (
        ValidationError,
        RequestValidationError,
        ResponseValidationError,
        StarletteHTTPException,
        HTTPException,
    ):
        return
    except Exception:
        return


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
