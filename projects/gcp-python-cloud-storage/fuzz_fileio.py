#!/usr/bin/python3
# Copyright 2022 Google LLC
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
import mock

with atheris.instrument_imports():
    from google.cloud.storage.fileio import BlobReader


global_data = None
def TestOneInput(data):
    global_data = data
    fdp = atheris.FuzzedDataProvider(data)

    blob = mock.Mock()
    def read_fuzz_data(start=0, end=None, **_):
        return global_data[start:end]

    blob.download_as_bytes = mock.Mock(side_effect=read_fuzz_data)
    blob.size = len(data)
    blob.chunk_size = None
    download_kwargs = {"if_metageneration_match": 1}
    reader = BlobReader(blob, **download_kwargs)
    try:
        reader.read(fdp.ConsumeIntInRange(0, len(data)*2))
    except UnicodeDecodeError:
        return

    reader.seek(
        pos = fdp.ConsumeIntInRange(0, len(data)*2),
        whence = fdp.ConsumeIntInRange(0, 2)
    )


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
