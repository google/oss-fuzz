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

"""Fuzz trimesh's archive loaders.

`_load_compressed` unpacks zip/tar archives and loads whatever is inside, which
is a different and higher-risk surface than the single-file parsers: entry names
are attacker-controlled (path traversal), entry sizes are attacker-declared
(decompression bombs), and the contained files then flow into every other loader.

Kept separate from fuzz_load.py so the two corpora do not dilute each other — an
archive seed is useless to a plain .stl target and vice versa.
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

# Exactly the keys of `compressed_loaders` in trimesh/exchange/load.py.
# There is no plain "tar" key — only the two compressed tar variants.
ARCHIVE_TYPES = ["zip", "tar.gz", "tar.bz2", "bz2"]

EXPECTED = (
    ValueError,
    IndexError,
    KeyError,
    TypeError,
    AttributeError,
    NotImplementedError,
    EOFError,
    UnicodeDecodeError,
    OSError,          # bz2/gzip raise these on malformed streams
    StopIteration,
    # BadZipFile and TarError derive from Exception, not OSError, so they have
    # to be listed explicitly.
    zipfile.BadZipFile,
    tarfile.TarError,
    lzma.LZMAError,
    zlib.error,
)


def TestOneInput(data):
    if len(data) < 2:
        return

    fdp = atheris.FuzzedDataProvider(data)
    file_type = ARCHIVE_TYPES[fdp.ConsumeIntInRange(0, len(ARCHIVE_TYPES) - 1)]
    # Atheris spells this ConsumeBytes(remaining_bytes()); ConsumeRemainingBytes()
    # is the C++ FuzzedDataProvider API and does not exist here.
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
