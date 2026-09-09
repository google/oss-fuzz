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
# - fastapi/applications.py
# Delta:
# - fastapi/applications.py >= 60%

import sys
from contextlib import asynccontextmanager

import atheris

with atheris.instrument_imports():
    import fastapi.applications as applications_mod
    from fastapi import Depends, HTTPException, Query
    from fastapi.exceptions import RequestValidationError, ResponseValidationError
    from fastapi.middleware.gzip import GZipMiddleware
    from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
    from fastapi.middleware.trustedhost import TrustedHostMiddleware
    from fastapi.testclient import TestClient
    from pydantic import ValidationError
    from starlette.requests import Request
    from starlette.responses import JSONResponse, PlainTextResponse
    from starlette.exceptions import HTTPException as StarletteHTTPException

    import fastapi_fuzz_utils as fuzz


def build_app(fdp: atheris.FuzzedDataProvider) -> applications_mod.FastAPI:
    title = "FastAPI " + fuzz.segment(fdp, 10)
    version = f"{fdp.ConsumeIntInRange(0, 9)}.{fdp.ConsumeIntInRange(0, 9)}.{fdp.ConsumeIntInRange(0, 9)}"
    openapi_url = "/openapi.json" if fdp.ConsumeBool() else None
    docs_url = "/docs" if fdp.ConsumeBool() else None
    redoc_url = "/redoc" if fdp.ConsumeBool() else None
    events: list[str] = []

    @asynccontextmanager
    async def lifespan(app):
        events.append("startup")
        yield {"events": events}
        events.append("shutdown")

    app = applications_mod.FastAPI(
        title=title,
        version=version,
        summary=fuzz.text(fdp, 24) or None,
        description=fuzz.text(fdp, 48),
        openapi_url=openapi_url,
        docs_url=docs_url,
        redoc_url=redoc_url,
        swagger_ui_parameters={"deepLinking": fdp.ConsumeBool(), "displayRequestDuration": fdp.ConsumeBool()},
        lifespan=lifespan,
        generate_unique_id_function=lambda route: "app-" + (route.name or "route"),
    )

    if fdp.ConsumeBool():
        app.add_middleware(GZipMiddleware, minimum_size=1)
    if fdp.ConsumeBool():
        app.add_middleware(HTTPSRedirectMiddleware)
    if fdp.ConsumeBool():
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=["testserver", "*.example.com"])

    def dep(flag: bool = Query(default=False)) -> bool:
        return flag

    @app.get("/ping")
    async def ping(flag: bool = Depends(dep)) -> dict[str, object]:
        return {"ok": True, "flag": flag}

    @app.get("/text")
    async def text_route() -> PlainTextResponse:
        return PlainTextResponse("ok")

    @app.get("/http-error")
    async def http_error() -> None:
        raise HTTPException(status_code=418, detail="boom")

    @app.get("/value-error")
    async def value_error() -> None:
        raise ValueError("bad")

    async def value_error_handler(request: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse({"detail": str(exc), "path": request.url.path}, status_code=499)

    app.add_exception_handler(ValueError, value_error_handler)
    app.add_exception_handler(404, value_error_handler)
    app.setup()
    return app


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    try:
        app = build_app(fdp)
        with TestClient(app, raise_server_exceptions=False) as client:
            client.get("/ping", params={"flag": "true" if fdp.ConsumeBool() else "false"}, headers={"host": "testserver"})
            client.get("/text", headers={"host": "testserver"})
            client.get("/http-error", headers={"host": "testserver"})
            client.get("/value-error", headers={"host": "testserver"})
            client.get("/missing", headers={"host": "testserver"})

            if app.openapi_url:
                client.get(app.openapi_url, headers={"host": "testserver"})
            if app.docs_url:
                client.get(app.docs_url, headers={"host": "testserver"})
            if app.redoc_url:
                client.get(app.redoc_url, headers={"host": "testserver"})

            app.openapi()
            app.openapi()
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
