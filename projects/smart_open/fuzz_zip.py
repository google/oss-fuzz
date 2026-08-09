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
import os
with atheris.instrument_imports():
    from smart_open import open
    import zipfile
    import tempfile

def TestInput(data):
    if len(data) < 10:
      return

    fdp = atheris.FuzzedDataProvider(data)

    tmp = tempfile.NamedTemporaryFile(prefix=fdp.ConsumeString(10), suffix=fdp.ConsumeString(4), delete=False)
    filestr = fdp.ConsumeString(100)

    with open(tmp.name, 'wb') as f:
        with zipfile.ZipFile(f, 'w') as zip:
            zip.writestr(fdp.ConsumeString(10), filestr)
            zip.writestr(fdp.ConsumeString(10), filestr)

    with open(tmp.name, 'rb') as f:
        with zipfile.ZipFile(f) as zip:
            for info in zip.infolist():
                file_bytes = zip.read(info.filename)
                assert filestr == file_bytes.decode('utf-8')
    os.unlink(tmp.name)

def main():
    atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
    atheris.instrument_all()
    atheris.Fuzz()

if __name__ == "__main__":
  main()
