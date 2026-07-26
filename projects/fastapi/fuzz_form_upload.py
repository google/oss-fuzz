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
# - fastapi/datastructures.py
# - fastapi/params.py
# - fastapi/dependencies/utils.py

import io
import sys

import atheris

with atheris.instrument_imports():
    from fastapi import FastAPI, File, Form, UploadFile
    from fastapi import datastructures as fastapi_datastructures
    from fastapi import routing as fastapi_routing
    from fastapi.dependencies import utils as dep_utils
    from fastapi.exceptions import RequestValidationError, ResponseValidationError
    from fastapi.testclient import TestClient
    from pydantic import ValidationError
    from starlette.datastructures import FormData
    from starlette.exceptions import HTTPException as StarletteHTTPException

    import fastapi_fuzz_utils as fuzz

app = FastAPI()


@app.post("/upload")
async def upload_route(
    file: UploadFile = File(...),
    note: str = Form(default=""),
    count: int = Form(default=0),
) -> dict[str, object]:
    data = await file.read()
    return {"filename": file.filename, "size": len(data), "note": note, "count": count}


@app.post("/upload-list")
async def upload_list_route(
    files: list[UploadFile] = File(...),
    tag: str | None = Form(default=None),
) -> dict[str, object]:
    sizes = []
    for file in files:
        sizes.append(len(await file.read()))
    return {"sizes": sizes, "tag": tag}


client = TestClient(app, raise_server_exceptions=False)
routes = {
    route.path: route
    for route in app.routes
    if isinstance(route, fastapi_routing.APIRoute)
}


async def exercise_upload(name: str, data: bytes) -> None:
    upload = fastapi_datastructures.UploadFile(
        filename=name,
        file=io.BytesIO(data),
        size=len(data),
    )
    fastapi_datastructures.UploadFile._validate(upload, {})
    await upload.read()
    await upload.seek(0)
    await upload.write(data[:8])
    await upload.seek(0)
    await upload.read()
    await upload.close()


def make_upload(name: str, data: bytes) -> fastapi_datastructures.UploadFile:
    return fastapi_datastructures.UploadFile(
        filename=name,
        file=io.BytesIO(data),
        size=len(data),
    )


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    try:
        filename = fuzz.segment(fdp, 16) + ".bin"
        content = fdp.ConsumeBytes(128)
        note = fuzz.text(fdp, 24)
        count = fdp.ConsumeIntInRange(-20, 120)

        fuzz.run(exercise_upload(filename, content))
        try:
            fastapi_datastructures.UploadFile._validate("bad", {})
        except Exception:
            pass

        if fdp.ConsumeBool():
            client.post(
                "/upload",
                data={"note": note, "count": str(count)},
                files={"file": (filename, content, "application/octet-stream")},
            )

            route = routes["/upload"]
            flat = dep_utils.get_flat_dependant(route.dependant)
            embed = dep_utils._should_embed_body_fields(flat.body_params)
            form = FormData(
                [
                    ("note", note),
                    ("count", str(count)),
                    ("file", make_upload(filename, content)),
                ]
            )
            fuzz.run(
                dep_utils.request_body_to_args(
                    body_fields=flat.body_params,
                    received_body=form,
                    embed_body_fields=embed,
                )
            )
        else:
            files = []
            form_items: list[tuple[str, object]] = [("tag", note)]
            for _ in range(fdp.ConsumeIntInRange(1, 3)):
                current_name = fuzz.segment(fdp, 12) + ".bin"
                current_data = fdp.ConsumeBytes(64)
                files.append(("files", (current_name, current_data, "application/octet-stream")))
                form_items.append(("files", make_upload(current_name, current_data)))

            client.post("/upload-list", data={"tag": note}, files=files)

            route = routes["/upload-list"]
            flat = dep_utils.get_flat_dependant(route.dependant)
            embed = dep_utils._should_embed_body_fields(flat.body_params)
            fuzz.run(
                dep_utils.request_body_to_args(
                    body_fields=flat.body_params,
                    received_body=FormData(form_items),
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
