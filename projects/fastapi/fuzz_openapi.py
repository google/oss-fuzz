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
# - fastapi/openapi/utils.py
# - fastapi/openapi/models.py

import sys

import atheris

with atheris.instrument_imports():
    from fastapi import Body, FastAPI, Header, Query, Security
    from fastapi import routing as fastapi_routing
    from fastapi.dependencies import utils as dep_utils
    from fastapi.exceptions import RequestValidationError, ResponseValidationError
    from fastapi.openapi import models as openapi_models
    from fastapi.openapi import utils as openapi_utils
    from fastapi.security import APIKeyHeader, HTTPBearer, OAuth2PasswordBearer
    from pydantic import BaseModel, ValidationError
    from starlette.exceptions import HTTPException as StarletteHTTPException

    import fastapi_fuzz_utils as fuzz


class Item(BaseModel):
    name: str
    size: int


class CreateEnvelope(BaseModel):
    item: Item
    enabled: bool = False


class ReadEnvelope(BaseModel):
    ok: bool
    item: Item | None = None


def build_app(fdp: atheris.FuzzedDataProvider) -> FastAPI:
    title = "FastAPI " + fuzz.segment(fdp, 12)
    version = f"{fdp.ConsumeIntInRange(0, 9)}.{fdp.ConsumeIntInRange(0, 9)}.{fdp.ConsumeIntInRange(0, 9)}"
    summary = fuzz.text(fdp, 32) or None
    description = fuzz.text(fdp, 64) or None

    app = FastAPI(title=title, version=version, summary=summary, description=description)

    bearer = HTTPBearer(auto_error=False)
    oauth2 = OAuth2PasswordBearer(tokenUrl="/token", auto_error=False, scopes={"read": "Read"})
    api_key = APIKeyHeader(name="x-key", auto_error=False)

    added = 0

    if fdp.ConsumeBool():
        @app.get("/items/{item_id}", tags=["items"], responses={404: {"description": "missing"}})
        async def read_item(item_id: int, q: str | None = Query(default=None)) -> dict[str, object]:
            return {"ok": True, "item": {"name": q or "x", "size": item_id}}

        added += 1

    if fdp.ConsumeBool():
        @app.post("/items", response_model=ReadEnvelope, tags=["write"])
        async def create_item(
            payload: CreateEnvelope,
            force: bool = Body(default=False, embed=True),
        ) -> dict[str, object]:
            return {"ok": not force, "item": payload.item.model_dump()}

        added += 1

    if fdp.ConsumeBool():
        @app.get("/bearer", tags=["secure"])
        async def bearer_view(auth=Security(bearer)) -> dict[str, object]:
            return {"ok": bool(auth), "item": None}

        added += 1

    if fdp.ConsumeBool():
        @app.get("/oauth2", tags=["secure"])
        async def oauth_view(token: str | None = Security(oauth2, scopes=["read"])) -> dict[str, object]:
            return {"ok": bool(token), "item": None}

        added += 1

    if fdp.ConsumeBool():
        @app.get("/api-key", tags=["secure"])
        async def api_key_view(
            key: str | None = Security(api_key),
            x_trace_id: str | None = Header(default=None, alias="x-trace-id"),
        ) -> dict[str, object]:
            return {"ok": bool(key), "trace": x_trace_id, "item": None}

        added += 1

    if not added:
        @app.get("/fallback")
        async def fallback() -> dict[str, bool]:
            return {"ok": True}

    return app


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    try:
        app = build_app(fdp)
        spec = openapi_utils.get_openapi(
            title=app.title,
            version=app.version,
            summary=app.summary,
            description=app.description,
            routes=app.routes,
            tags=[{"name": "items", "description": fuzz.text(fdp, 20)}] if fdp.ConsumeBool() else None,
            servers=[{"url": "https://example.com", "description": fuzz.text(fdp, 20)}] if fdp.ConsumeBool() else None,
            contact={"name": fuzz.segment(fdp, 8), "email": "user@example.com"} if fdp.ConsumeBool() else None,
            license_info={"name": "MIT"} if fdp.ConsumeBool() else None,
            separate_input_output_schemas=fdp.ConsumeBool(),
        )

        model = openapi_models.OpenAPI.model_validate(spec)
        model.model_dump(by_alias=True, exclude_none=True)

        flows = openapi_models.OAuthFlows(
            password=openapi_models.OAuthFlowPassword(tokenUrl="/token", scopes={"read": "Read"}),
            authorizationCode=(
                openapi_models.OAuthFlowAuthorizationCode(
                    authorizationUrl="/auth",
                    tokenUrl="/token",
                )
                if fdp.ConsumeBool()
                else None
            ),
        )
        openapi_models.OAuth2(flows=flows)
        openapi_models.APIKey(**{"in": "header"}, name="x-key")
        openapi_models.HTTPBearer(bearerFormat=fuzz.text(fdp, 12) or None)

        for route in app.routes:
            if isinstance(route, fastapi_routing.APIRoute):
                flat = dep_utils.get_flat_dependant(route.dependant, skip_repeats=True)
                openapi_utils.get_openapi_security_definitions(flat)
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
