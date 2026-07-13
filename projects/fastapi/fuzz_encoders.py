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
# - fastapi/encoders.py

import dataclasses
import datetime
import decimal
import pathlib
import sys
from collections import deque
from enum import Enum
from uuid import UUID

import atheris

with atheris.instrument_imports():
    from fastapi import encoders as fastapi_encoders
    from fastapi.exceptions import RequestValidationError, ResponseValidationError
    from pydantic import BaseModel, ValidationError
    from starlette.exceptions import HTTPException as StarletteHTTPException

    import fastapi_fuzz_utils as fuzz


class Role(Enum):
    ADMIN = "admin"
    USER = "user"


@dataclasses.dataclass
class Box:
    name: str
    count: int


class ModelBox(BaseModel):
    name: str
    count: int | None = None
    when: datetime.datetime | None = None


class AttrBox:
    def __init__(self, payload: object):
        self.payload = payload


class PairBox:
    def __init__(self, payload: dict[str, object]):
        self.payload = payload

    def __iter__(self):
        return iter(self.payload.items())


class BrokenBox:
    def __iter__(self):
        raise TypeError("bad iterator")


def build_obj(fdp: atheris.FuzzedDataProvider, depth: int = 0) -> object:
    limit = 9 if depth >= 2 else 15
    kind = fdp.ConsumeIntInRange(0, limit)
    if kind == 0:
        return None
    if kind == 1:
        return fdp.ConsumeIntInRange(-1000, 1000)
    if kind == 2:
        return round(fdp.ConsumeFloatInRange(-1000.0, 1000.0), 3)
    if kind == 3:
        return fuzz.text(fdp, 40)
    if kind == 4:
        return fdp.ConsumeBool()
    if kind == 5:
        return fdp.ConsumeBytes(20)
    if kind == 6:
        return decimal.Decimal(str(fdp.ConsumeIntInRange(-1000, 1000)))
    if kind == 7:
        return pathlib.Path("/tmp") / fuzz.segment(fdp, 12)
    if kind == 8:
        raw = fdp.ConsumeBytes(16).ljust(16, b"\x00")
        return UUID(bytes=raw[:16])
    if kind == 9:
        return datetime.datetime.fromtimestamp(
            fdp.ConsumeIntInRange(0, 2_000_000_000),
            tz=datetime.timezone.utc,
        )
    if kind == 10:
        return Role.ADMIN if fdp.ConsumeBool() else Role.USER
    if kind == 11:
        return Box(name=fuzz.segment(fdp, 16), count=fdp.ConsumeIntInRange(-20, 20))
    if kind == 12:
        return ModelBox(
            name=fuzz.segment(fdp, 16),
            count=fdp.ConsumeIntInRange(-20, 20),
            when=datetime.datetime.fromtimestamp(
                fdp.ConsumeIntInRange(0, 2_000_000_000),
                tz=datetime.timezone.utc,
            ),
        )
    if kind == 13:
        return [build_obj(fdp, depth + 1) for _ in range(fdp.ConsumeIntInRange(0, 3))]
    if kind == 14:
        return {
            fuzz.segment(fdp, 8): build_obj(fdp, depth + 1)
            for _ in range(fdp.ConsumeIntInRange(0, 3))
        }
    if kind == 15:
        return deque(
            build_obj(fdp, depth + 1) for _ in range(fdp.ConsumeIntInRange(0, 3))
        )
    if kind == 16:
        return {fuzz.segment(fdp, 8) for _ in range(fdp.ConsumeIntInRange(0, 3))}
    if kind == 17:
        return AttrBox(build_obj(fdp, depth + 1))
    if kind == 18:
        return PairBox(
            {
                fuzz.segment(fdp, 8): build_obj(fdp, depth + 1)
                for _ in range(fdp.ConsumeIntInRange(0, 3))
            }
        )
    return BrokenBox()


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    try:
        value = build_obj(fdp)
        include = {fuzz.segment(fdp, 8)} if fdp.ConsumeBool() else None
        exclude = {fuzz.segment(fdp, 8)} if fdp.ConsumeBool() else None
        custom_encoder = {AttrBox: lambda obj: {"payload": obj.payload}} if fdp.ConsumeBool() else None

        fastapi_encoders.generate_encoders_by_class_tuples(fastapi_encoders.ENCODERS_BY_TYPE)
        fastapi_encoders.decimal_encoder(decimal.Decimal(str(fdp.ConsumeIntInRange(-100, 100))))
        fastapi_encoders.jsonable_encoder(
            value,
            include=include,
            exclude=exclude,
            exclude_unset=fdp.ConsumeBool(),
            exclude_defaults=fdp.ConsumeBool(),
            exclude_none=fdp.ConsumeBool(),
            custom_encoder=custom_encoder,
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
