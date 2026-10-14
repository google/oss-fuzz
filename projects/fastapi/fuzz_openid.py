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
# - fastapi/security/open_id_connect_url.py
# Delta:
# - fastapi/security/open_id_connect_url.py >= 70%

import sys

import atheris

with atheris.instrument_imports():
    import fastapi.security.open_id_connect_url as openid_mod
    from fastapi import Depends, FastAPI
    from fastapi.exceptions import RequestValidationError, ResponseValidationError
    from fastapi.testclient import TestClient
    from pydantic import ValidationError
    from starlette.exceptions import HTTPException as StarletteHTTPException

    import fastapi_fuzz_utils as fuzz


required_scheme = openid_mod.OpenIdConnect(
    openIdConnectUrl="https://example.com/.well-known/openid-configuration"
)
optional_scheme = openid_mod.OpenIdConnect(
    openIdConnectUrl="https://example.com/.well-known/openid-configuration",
    auto_error=False,
)

app = FastAPI()


@app.get("/openid")
async def openid_route(token: str | None = Depends(optional_scheme)) -> dict[str, object]:
    return {"token": token}


@app.get("/openid-required")
async def openid_required_route(token: str = Depends(required_scheme)) -> dict[str, str]:
    return {"token": token}


client = TestClient(app, raise_server_exceptions=False)


async def exercise_direct(request) -> None:
    for scheme in [required_scheme, optional_scheme]:
        try:
            await scheme(request)
        except Exception:
            pass


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    try:
        url = "https://example.com/" + fuzz.path(fdp)
        scheme = openid_mod.OpenIdConnect(
            openIdConnectUrl=url,
            scheme_name=fuzz.segment(fdp, 12),
            description=fuzz.text(fdp, 24) or None,
            auto_error=fdp.ConsumeBool(),
        )
        scheme.make_not_authenticated_error()

        auth_header = None
        if fdp.ConsumeBool():
            auth_header = "Bearer " + fuzz.token(fdp, 24)

        headers_map = {"host": "testserver"}
        if auth_header:
            headers_map["authorization"] = auth_header

        client.get("/openid", headers=headers_map)
        client.get("/openid-required", headers=headers_map)

        request = fuzz.make_request("GET", "/openid", headers_map=headers_map)
        fuzz.run(exercise_direct(request))
        try:
            fuzz.run(scheme(request))
        except Exception:
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
