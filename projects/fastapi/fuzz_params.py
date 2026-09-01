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
# - fastapi/utils.py

import sys

import atheris

with atheris.instrument_imports():
    from fastapi import Cookie, FastAPI, Header, Path, Query
    from fastapi import params as fastapi_params
    from fastapi import utils as fastapi_utils
    from fastapi.exceptions import RequestValidationError, ResponseValidationError
    from fastapi.testclient import TestClient
    from pydantic import ValidationError
    from starlette.exceptions import HTTPException as StarletteHTTPException

    import fastapi_fuzz_utils as fuzz

app = FastAPI()


@app.get("/params/{item_id}")
async def params_route(
    item_id: int = Path(..., ge=-128, le=128),
    q: str | None = Query(default=None, min_length=0, max_length=32),
    limit: int = Query(default=10, ge=0, le=100),
    x_count: int | None = Header(default=None, alias="x-count"),
    session: str | None = Cookie(default=None, alias="session"),
) -> dict[str, object]:
    return {
        "item_id": item_id,
        "q": q,
        "limit": limit,
        "x_count": x_count,
        "session": session,
    }


@app.get("/lists/{slug}")
async def list_route(
    slug: str = Path(..., min_length=1, max_length=20),
    tags: list[int] | None = Query(default=None),
    flag: bool = Query(default=False),
    x_trace_id: str | None = Header(default=None, alias="x-trace-id"),
) -> dict[str, object]:
    return {"slug": slug, "tags": tags, "flag": flag, "trace": x_trace_id}


client = TestClient(app, raise_server_exceptions=False)


def build_fields(fdp: atheris.FuzzedDataProvider) -> None:
    min_len = fdp.ConsumeIntInRange(0, 4)
    max_len = fdp.ConsumeIntInRange(min_len, 24)

    query_info = fastapi_params.Query(
        default=None,
        min_length=min_len,
        max_length=max_len,
        alias=fuzz.segment(fdp, 8) if fdp.ConsumeBool() else None,
        pattern="^[A-Za-z0-9_-]*$" if fdp.ConsumeBool() else None,
    )
    fastapi_utils.create_model_field("q", str | None, field_info=query_info, alias=query_info.alias)

    path_info = fastapi_params.Path(title=fuzz.text(fdp, 16) or None, ge=-100.0, le=100.0)
    fastapi_utils.create_model_field("item_id", int, field_info=path_info, alias=path_info.alias)

    header_info = fastapi_params.Header(default=None, alias="x-count")
    fastapi_utils.create_model_field("x_count", int | None, field_info=header_info, alias=header_info.alias)

    cookie_info = fastapi_params.Cookie(default=None, alias="session")
    fastapi_utils.create_model_field("session", str | None, field_info=cookie_info, alias=cookie_info.alias)

    body_info = fastapi_params.Body(default=None, embed=fdp.ConsumeBool())
    fastapi_utils.create_model_field("body", dict[str, int] | None, field_info=body_info, alias=body_info.alias)

    form_info = fastapi_params.Form(default=None, alias="name")
    fastapi_utils.create_model_field("name", str | None, field_info=form_info, alias=form_info.alias)

    file_info = fastapi_params.File(default=None, alias="upload")
    fastapi_utils.create_model_field("upload", bytes | None, field_info=file_info, alias=file_info.alias)

    fastapi_utils.get_path_param_names(f"/items/{{{fuzz.segment(fdp, 6)}}}/{{{fuzz.segment(fdp, 6)}}}")


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    try:
        build_fields(fdp)

        if fdp.ConsumeBool():
            path = f"/params/{fdp.ConsumeIntInRange(-256, 256) if fdp.ConsumeBool() else fuzz.segment(fdp)}"
            query = [
                ("q", fuzz.scalar_text(fdp)),
                ("limit", str(fdp.ConsumeIntInRange(-10, 120))),
            ]
            headers_map = {"x-count": str(fdp.ConsumeIntInRange(-50, 150))}
            cookies = {"session": fuzz.token(fdp, 16)}
            client.get(path, params=query, headers=headers_map, cookies=cookies)
        else:
            path = f"/lists/{fuzz.segment(fdp)}"
            query = [
                ("flag", "true" if fdp.ConsumeBool() else "false"),
            ]
            for _ in range(fdp.ConsumeIntInRange(0, 4)):
                query.append(("tags", str(fdp.ConsumeIntInRange(-20, 20))))
            headers_map = {"x-trace-id": fuzz.token(fdp, 16)}
            client.get(path, params=query, headers=headers_map)
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
