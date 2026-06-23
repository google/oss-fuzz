#!/usr/bin/python3
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
#
################################################################################

import sys
import atheris
import io
import zipfile
import zlib

with atheris.instrument_imports():
    import docx
    from docx.opc.exceptions import PackageNotFoundError
    import lxml.etree

def TestOneInput(data):
    # A valid .docx file is a ZIP archive
    if len(data) < 22 or not data.startswith(b"PK"):
        return

    try:
        stream = io.BytesIO(data)
        doc = docx.Document(stream)
        
        # Force deep traversal of the XML tree
        for para in doc.paragraphs:
            _ = para.text
            
        for table in doc.tables:
            for row in table.rows:
                for cell in row.cells:
                    _ = cell.text
                    
        _ = doc.core_properties.author
        _ = doc.core_properties.title

    except (
        # Catch standard expected robustness errors from malformed data
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        PackageNotFoundError,
        lxml.etree.XMLSyntaxError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        AttributeError,
        NotImplementedError,
        zlib.error,
        EOFError,
        RuntimeError,
        OSError
    ):
        pass

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()