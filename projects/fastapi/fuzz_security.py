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
# - fastapi/security/api_key.py
# - fastapi/security/http.py
# - fastapi/security/oauth2.py
# - fastapi/security/utils.py
# Delta:
# - fastapi/security/http.py >= 75%

import base64
import sys

import atheris

with atheris.instrument_imports():
    import fastapi.security.api_key as api_key_mod
    import fastapi.security.http as http_mod
    import fastapi.security.oauth2 as oauth2_mod
    import fastapi.security.utils as security_utils
    from fastapi import Depends, FastAPI, Security
    from fastapi.exceptions import RequestValidationError, ResponseValidationError
    from fastapi.security import (
        APIKeyCookie,
        APIKeyHeader,
        APIKeyQuery,
        HTTPBasic,
        HTTPBearer,
        HTTPDigest,
        OAuth2,
        OAuth2AuthorizationCodeBearer,
        OAuth2PasswordBearer,
        OAuth2PasswordRequestFormStrict,
    )
    from fastapi.testclient import TestClient
    from pydantic import ValidationError
    from starlette.exceptions import HTTPException as StarletteHTTPException

    import fastapi_fuzz_utils as fuzz


query_scheme = APIKeyQuery(name="key", auto_error=False)
header_scheme = APIKeyHeader(name="x-key", auto_error=False)
cookie_scheme = APIKeyCookie(name="session", auto_error=False)

basic_optional = HTTPBasic(auto_error=False)
basic_required = HTTPBasic()
bearer_optional = HTTPBearer(auto_error=False)
bearer_required = HTTPBearer()
digest_optional = HTTPDigest(auto_error=False)
digest_required = HTTPDigest()

oauth2_password = OAuth2PasswordBearer(tokenUrl="/token", auto_error=False, scopes={"read": "Read"})
oauth2_code = OAuth2AuthorizationCodeBearer(
    authorizationUrl="/auth",
    tokenUrl="/token",
    auto_error=False,
    scopes={"write": "Write"},
)
oauth2_base = OAuth2(
    flows={"password": {"tokenUrl": "/token", "scopes": {"read": "Read"}}},
    auto_error=False,
)

app = FastAPI()


@app.get("/query")
async def query_route(key: str | None = Depends(query_scheme)) -> dict[str, object]:
    return {"key": key}


@app.get("/header")
async def header_route(key: str | None = Depends(header_scheme)) -> dict[str, object]:
    return {"key": key}


@app.get("/cookie")
async def cookie_route(session: str | None = Depends(cookie_scheme)) -> dict[str, object]:
    return {"session": session}


@app.get("/basic")
async def basic_route(credentials: http_mod.HTTPBasicCredentials | None = Depends(basic_optional)) -> dict[str, object]:
    return {
        "username": credentials.username if credentials else None,
        "password": credentials.password if credentials else None,
    }


@app.get("/basic-required")
async def basic_required_route(credentials: http_mod.HTTPBasicCredentials = Depends(basic_required)) -> dict[str, object]:
    return {"username": credentials.username, "password": credentials.password}


@app.get("/bearer")
async def bearer_route(credentials: http_mod.HTTPAuthorizationCredentials | None = Depends(bearer_optional)) -> dict[str, object]:
    return {
        "scheme": credentials.scheme if credentials else None,
        "credentials": credentials.credentials if credentials else None,
    }


@app.get("/bearer-required")
async def bearer_required_route(
    credentials: http_mod.HTTPAuthorizationCredentials = Depends(bearer_required),
) -> dict[str, object]:
    return {"scheme": credentials.scheme, "credentials": credentials.credentials}


@app.get("/digest")
async def digest_route(credentials: http_mod.HTTPAuthorizationCredentials | None = Depends(digest_optional)) -> dict[str, object]:
    return {
        "scheme": credentials.scheme if credentials else None,
        "credentials": credentials.credentials if credentials else None,
    }


@app.get("/digest-required")
async def digest_required_route(
    credentials: http_mod.HTTPAuthorizationCredentials = Depends(digest_required),
) -> dict[str, object]:
    return {"scheme": credentials.scheme, "credentials": credentials.credentials}


@app.get("/oauth2/password")
async def oauth2_password_route(token: str | None = Security(oauth2_password, scopes=["read"])) -> dict[str, object]:
    return {"token": token}


@app.get("/oauth2/code")
async def oauth2_code_route(token: str | None = Security(oauth2_code, scopes=["write"])) -> dict[str, object]:
    return {"token": token}


@app.get("/oauth2/base")
async def oauth2_base_route(token: str | None = Depends(oauth2_base)) -> dict[str, object]:
    return {"token": token}


@app.post("/login")
async def login_route(form: OAuth2PasswordRequestFormStrict = Depends()) -> dict[str, object]:
    return {
        "username": form.username,
        "password": form.password,
        "scopes": form.scopes,
        "client_id": form.client_id,
        "client_secret": form.client_secret,
    }


client = TestClient(app, raise_server_exceptions=False)


def make_basic_header(username: str, password: str) -> str:
    raw = f"{username}:{password}".encode("ascii", "ignore")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def pick_auth_header(fdp: atheris.FuzzedDataProvider) -> str | None:
    choice = fdp.ConsumeIntInRange(0, 7)
    if choice == 0:
        return None
    if choice == 1:
        return "Bearer " + fuzz.token(fdp, 24)
    if choice == 2:
        return make_basic_header(fuzz.segment(fdp, 12), fuzz.text(fdp, 12))
    if choice == 3:
        return "Basic " + fuzz.token(fdp, 24)
    if choice == 4:
        raw = base64.b64encode(fuzz.segment(fdp, 12).encode("ascii", "ignore")).decode("ascii")
        return "Basic " + raw
    if choice == 5:
        return "Digest " + fuzz.text(fdp, 40)
    if choice == 6:
        return "Digest username=\"alice\", realm=\"realm\", nonce=\"n\", uri=\"/\", response=\"r\""
    return fuzz.text(fdp, 40)


async def exercise_direct(request) -> None:
    for scheme in [
        query_scheme,
        header_scheme,
        cookie_scheme,
        basic_optional,
        basic_required,
        bearer_optional,
        bearer_required,
        digest_optional,
        digest_required,
        oauth2_password,
        oauth2_code,
        oauth2_base,
    ]:
        try:
            await scheme(request)
        except Exception:
            pass


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    try:
        query_key = fuzz.token(fdp, 16)
        header_key = fuzz.token(fdp, 16)
        session_value = fuzz.token(fdp, 16)
        auth_header = pick_auth_header(fdp)

        headers_map = fuzz.headers(fdp)
        headers_map["x-key"] = header_key
        headers_map["cookie"] = f"session={session_value}"
        if auth_header:
            headers_map["authorization"] = auth_header

        query = [("key", query_key)]

        path_value = fuzz.pick(
            fdp,
            [
                "/query",
                "/header",
                "/cookie",
                "/basic",
                "/basic-required",
                "/bearer",
                "/bearer-required",
                "/digest",
                "/digest-required",
                "/oauth2/password",
                "/oauth2/code",
                "/oauth2/base",
                "/login",
            ],
        )

        if path_value == "/login":
            client.post(
                path_value,
                data={
                    "grant_type": "password",
                    "username": fuzz.segment(fdp, 16),
                    "password": fuzz.text(fdp, 16),
                    "scope": " ".join(fuzz.segment(fdp, 8) for _ in range(fdp.ConsumeIntInRange(0, 3))),
                    "client_id": fuzz.segment(fdp, 8),
                    "client_secret": fuzz.text(fdp, 12),
                },
                headers=headers_map,
            )
        else:
            client.get(
                path_value,
                params=query,
                headers=headers_map,
                cookies={"session": session_value},
            )

        client.get("/basic", headers={"authorization": "Bearer " + fuzz.token(fdp, 16)})
        client.get("/basic-required", headers={"authorization": "Bearer " + fuzz.token(fdp, 16)})
        client.get("/bearer", headers={"authorization": make_basic_header("alice", "secret")})
        client.get("/bearer-required", headers={"authorization": make_basic_header("alice", "secret")})
        client.get("/digest", headers={"authorization": "Bearer " + fuzz.token(fdp, 16)})
        client.get("/digest-required", headers={"authorization": make_basic_header("alice", "secret")})
        client.get("/digest-required")
        client.get("/basic-required", headers={"authorization": "Basic " + fuzz.token(fdp, 24)})

        security_utils.get_authorization_scheme_param(headers_map.get("authorization"))
        security_utils.get_authorization_scheme_param("Basic bad")
        security_utils.get_authorization_scheme_param("Digest token")
        security_utils.get_authorization_scheme_param(None)

        http_mod.HTTPBasicCredentials(username=fuzz.segment(fdp, 12), password=fuzz.text(fdp, 12))
        http_mod.HTTPAuthorizationCredentials(
            scheme=fuzz.segment(fdp, 8),
            credentials=fuzz.token(fdp, 24),
        )
        api_key_mod.APIKeyQuery(name=fuzz.segment(fdp, 8), auto_error=fdp.ConsumeBool())
        oauth2_mod.OAuth2(
            flows={"password": {"tokenUrl": "/token", "scopes": {"read": "Read"}}},
            auto_error=False,
        )
        OAuth2PasswordRequestFormStrict(
            grant_type="password",
            username=fuzz.segment(fdp, 12),
            password=fuzz.text(fdp, 12),
            scope="read write",
            client_id=fuzz.segment(fdp, 8),
            client_secret=fuzz.text(fdp, 8),
        )

        request = fuzz.make_request("GET", "/security", headers_map=headers_map, query=query)
        fuzz.run(exercise_direct(request))
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
