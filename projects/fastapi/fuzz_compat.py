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
# - fastapi/_compat/__init__.py
# - fastapi/_compat/shared.py
# - fastapi/_compat/v2.py
# Delta:
# - fastapi/_compat/* >= 60%

import io
import sys

import atheris

with atheris.instrument_imports():
    import fastapi._compat as compat
    import fastapi._compat.shared as compat_shared
    import fastapi._compat.v2 as compat_v2
    from fastapi import Body, File, Form, Query, UploadFile
    from fastapi.utils import create_model_field
    from pydantic import BaseModel, ConfigDict, Field, ValidationError
    from starlette.datastructures import UploadFile as StarletteUploadFile

    import fastapi_fuzz_utils as fuzz


class CompatInner(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    count: int = 0


class CompatOuter(BaseModel):
    item: CompatInner
    tags: list[str] = []
    payload: bytes | None = None


def make_fields() -> list[compat.ModelField]:
    query_info = Query(default=None, min_length=0, max_length=16, alias="q")
    body_info = Body(default=None, embed=True)
    form_info = Form(default=None, alias="name")
    file_info = File(default=None, alias="upload")

    return [
        create_model_field("q", str | None, field_info=query_info, alias=query_info.alias),
        create_model_field("body", CompatOuter | None, field_info=body_info, alias=body_info.alias),
        create_model_field("name", str | None, field_info=form_info, alias=form_info.alias),
        create_model_field("upload", UploadFile | None, field_info=file_info, alias=file_info.alias),
        create_model_field("tags", list[int] | None, field_info=Query(default=None), alias="tags"),
        create_model_field("payload", bytes | None, field_info=File(default=None), alias="payload"),
    ]


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    try:
        fields = make_fields()
        model_fields = compat.get_cached_model_fields(CompatOuter)
        body_model = compat.create_body_model(fields=model_fields, model_name="CompatBody")
        body_fields = compat.get_cached_model_fields(body_model)

        compat.copy_field_info(field_info=fields[0].field_info, annotation=str | None)
        compat.copy_field_info(field_info=fields[1].field_info, annotation=CompatOuter | None)

        compat.field_annotation_is_scalar(str)
        compat.field_annotation_is_scalar(list[str])
        compat.field_annotation_is_scalar_sequence(list[int])
        compat.field_annotation_is_scalar_sequence(tuple[int, ...])
        compat.field_annotation_is_sequence(list[str])
        compat.value_is_sequence([1, 2, 3])
        compat.value_is_sequence("x")
        compat.is_bytes_or_nonable_bytes_annotation(bytes | None)
        compat.is_bytes_sequence_annotation(list[bytes])
        compat.is_uploadfile_or_nonable_uploadfile_annotation(UploadFile | None)
        compat.is_uploadfile_sequence_annotation(list[UploadFile])
        compat.lenient_issubclass(CompatOuter, BaseModel)
        compat.annotation_is_pydantic_v1(CompatOuter)
        compat_shared.is_pydantic_v1_model_instance(CompatOuter(item=CompatInner(name="x")))

        compat.is_scalar_field(fields[0])
        compat.is_scalar_field(fields[1])
        compat.serialize_sequence_value(field=fields[4], value=[fdp.ConsumeIntInRange(-5, 5) for _ in range(2)])
        compat.serialize_sequence_value(field=fields[5], value=[fdp.ConsumeBytes(4) for _ in range(2)])
        compat.get_missing_field_error(("body", "item"))

        name_map = compat.get_model_name_map({CompatInner, CompatOuter, body_model})
        field_mapping, definitions = compat.get_definitions(
            fields=model_fields + body_fields,
            model_name_map=name_map,
            separate_input_output_schemas=fdp.ConsumeBool(),
        )
        for field in model_fields + body_fields:
            compat.get_schema_from_model_field(
                field=field,
                model_name_map=name_map,
                field_mapping=field_mapping,
                separate_input_output_schemas=fdp.ConsumeBool(),
            )
        compat_v2.get_flat_models_from_fields(model_fields + body_fields, known_models=set())
        compat_v2.get_model_name_map({CompatInner, CompatOuter, body_model})

        upload = StarletteUploadFile(filename=fuzz.segment(fdp, 12) + ".bin", file=io.BytesIO(fdp.ConsumeBytes(16)))
        upload_field = create_model_field("upload", UploadFile, field_info=File(default=...), alias="upload")
        upload_field.validate(upload, {})

        model = CompatOuter(
            item=CompatInner(name=fuzz.segment(fdp, 12), count=fdp.ConsumeIntInRange(-10, 10)),
            tags=[fuzz.segment(fdp, 8) for _ in range(fdp.ConsumeIntInRange(0, 3))],
            payload=fdp.ConsumeBytes(8) or None,
        )
        for field in model_fields:
            field.validate(model.model_dump().get(field.name), {})
    except ValidationError:
        return
    except Exception:
        return


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
