#!/usr/bin/python3
# Copyright 2023 Google LLC
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

import atheris
import sys
from io import BytesIO

with atheris.instrument_imports():
    from pypdf import PdfWriter, PdfReader
    from pypdf.generic import AnnotationBuilder


@atheris.instrument_func
def TestInputOne(data):
    fdp = atheris.FuzzedDataProvider(data)

    try:
        dummy = BytesIO()
        writer = PdfWriter()

        # Construct PDF
        writer.add_metadata({
            f"/X{fdp.ConsumeUnicodeNoSurrogates(100)}": fdp.ConsumeUnicodeNoSurrogates(100)
        })
        rect = (10, 20, 30, 40)
        writer.add_annotation(page_number=0,
                              annotation=AnnotationBuilder.link(
                                  url=f"{fdp.ConsumeUnicodeNoSurrogates(100)}.com",
                                  rect=rect
                              ))
        # Encrypt
        key = fdp.ConsumeUnicodeNoSurrogates(sys.maxsize)
        writer.encrypt(key, algorithm="AES-256")
        writer.write(dummy)

        # Read Dummy PDF
        reader = PdfReader(dummy)

        if not reader.is_encrypted:
            raise Exception("Encryption error. Failed to encrypt stream")

        # Decrypt
        reader.decrypt(key)

        if reader.stream == dummy:
            raise Exception("Decryption error. Original stream != Decrypted stream")

    except Exception:
        return


if __name__ == '__main__':
    atheris.Setup(sys.argv, TestInputOne)
    atheris.Fuzz()
