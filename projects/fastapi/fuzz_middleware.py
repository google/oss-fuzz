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
# - fastapi/middleware/gzip.py
# - fastapi/middleware/httpsredirect.py
# - fastapi/middleware/trustedhost.py

import sys

import atheris

with atheris.instrument_imports():
    from fastapi import FastAPI
    from fastapi.exceptions import RequestValidationError, ResponseValidationError
    from fastapi.middleware.gzip import GZipMiddleware
    from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
    from fastapi.middleware.trustedhost import TrustedHostMiddleware
    from fastapi.testclient import TestClient
    from pydantic import ValidationError
    from starlette.exceptions import HTTPException as StarletteHTTPException
    from starlette.responses import PlainTextResponse

    import fastapi_fuzz_utils as fuzz

gzip_app = FastAPI()
gzip_app.add_middleware(GZipMiddleware, minimum_size=1)


@gzip_app.get("/gzip")
async def gzip_route() -> PlainTextResponse:
    return PlainTextResponse("z" * 4096)


https_app = FastAPI()
https_app.add_middleware(HTTPSRedirectMiddleware)


@https_app.get("/secure")
async def secure_route() -> dict[str, bool]:
    return {"ok": True}


trusted_app = FastAPI()
trusted_app.add_middleware(TrustedHostMiddleware, allowed_hosts=["testserver", "*.example.com"])


@trusted_app.get("/host")
async def host_route() -> dict[str, bool]:
    return {"ok": True}


gzip_client = TestClient(gzip_app, raise_server_exceptions=False)
https_client = TestClient(https_app, raise_server_exceptions=False)
trusted_client = TestClient(trusted_app, raise_server_exceptions=False)


async def plain_app(scope, receive, send) -> None:
    response = PlainTextResponse("ok" * 2048)
    await response(scope, receive, send)


gzip_middleware = GZipMiddleware(plain_app, minimum_size=1)
https_middleware = HTTPSRedirectMiddleware(plain_app)
trusted_middleware = TrustedHostMiddleware(
    plain_app,
    allowed_hosts=["testserver", "*.example.com"],
)


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    try:
        gzip_headers = fuzz.headers(fdp)
        gzip_headers["accept-encoding"] = "gzip"
        gzip_client.get("/gzip", headers=gzip_headers)

        trusted_headers = fuzz.headers(fdp)
        if fdp.ConsumeBool():
            trusted_headers["host"] = "testserver"
        else:
            trusted_headers["host"] = fuzz.segment(fdp, 12) + ".invalid"
        trusted_client.get("/host", headers=trusted_headers)

        https_client.get("/secure", headers=fuzz.headers(fdp), follow_redirects=False)

        gzip_messages: list[dict[str, object]] = []
        fuzz.run(
            gzip_middleware(
                fuzz.build_scope("GET", "/raw", headers_map={"host": "testserver", "accept-encoding": "gzip"}),
                fuzz.make_receive(),
                fuzz.make_send(gzip_messages),
            )
        )

        https_messages: list[dict[str, object]] = []
        fuzz.run(
            https_middleware(
                fuzz.build_scope("GET", "/secure", headers_map={"host": "testserver"}),
                fuzz.make_receive(),
                fuzz.make_send(https_messages),
            )
        )

        trusted_messages: list[dict[str, object]] = []
        fuzz.run(
            trusted_middleware(
                fuzz.build_scope("GET", "/host", headers_map=trusted_headers),
                fuzz.make_receive(),
                fuzz.make_send(trusted_messages),
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
