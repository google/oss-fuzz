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

"""Fuzz trimesh's mesh/scene loaders with format-directed input.

trimesh dispatches on `file_type`, so letting the fuzzer pick the format from the
first byte is far more efficient than hoping it guesses a magic number. Each
iteration selects a loader, then hands it the remaining bytes.
"""

import io
import lzma
import sys
import tarfile
import zipfile
import zlib

import atheris

with atheris.instrument_imports():
    import trimesh

# Keys taken from the loader registries in trimesh/exchange/, not guessed:
#   _stl/_ply/_obj/_off/_xyz/_binvox/_collada/_threedxml/_xaml/_three/_gltf_loaders
# Note `urdf` is deliberately absent — urdf.py only exports, it has no loader.
FORMATS = [
    # binary
    "stl", "ply", "binvox", "glb",
    # plaintext
    "obj", "off", "xyz", "gltf",
    # XML-backed — most likely to expose entity expansion / external entities
    "dae", "3dxml", "xaml",
    # zip-backed single files — path traversal in entry names
    "3mf", "zae",
]

# Exceptions a parser is *allowed* to raise on malformed input. Anything outside
# this set is a finding.
#
# Deliberately NOT listed:
#   RecursionError  — unbounded nesting is a real DoS (see the open pydicom SQ bug)
#   MemoryError     — attacker-controlled allocation from a header field
#   SystemError     — almost always a broken C extension
EXPECTED = (
    ValueError,
    IndexError,
    KeyError,
    TypeError,
    AttributeError,
    NotImplementedError,
    EOFError,
    UnicodeDecodeError,
    ZeroDivisionError,
    StopIteration,
    # The zip-backed formats (3dxml, 3mf, zae) hand the payload straight to
    # zipfile, so a malformed archive surfaces as BadZipFile rather than a
    # trimesh-level error. Same for the other container libraries.
    zipfile.BadZipFile,
    tarfile.TarError,
    lzma.LZMAError,
    zlib.error,
)


def TestOneInput(data):
    if len(data) < 2:
        return

    fdp = atheris.FuzzedDataProvider(data)
    file_type = FORMATS[fdp.ConsumeIntInRange(0, len(FORMATS) - 1)]
    # Atheris has no ConsumeRemainingBytes() — that is the C++ FuzzedDataProvider
    # API. The Python binding spells it ConsumeBytes(remaining_bytes()).
    payload = fdp.ConsumeBytes(fdp.remaining_bytes())
    if not payload:
        return

    try:
        trimesh.load(io.BytesIO(payload), file_type=file_type)
    except EXPECTED:
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
