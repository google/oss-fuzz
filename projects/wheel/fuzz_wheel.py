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
import sys
import atheris
import zipfile
from wheel.cli import unpack, WheelError


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  wheel_path = "/tmp/fuzzwheelfile-1.0-py27-none-any.whl"
  with open(wheel_path, "wb") as fuzz_file:
    fuzz_file.write(data)

  try:
    zipfile.ZipFile(wheel_path, "r", zipfile.ZIP_DEFLATED, allowZip64=True)
  except:
    # To focus on the wheel logic we only want to use zipfiles that
    # does not cause zipfile to break. This is because wheel does not
    # protect against this: e.g. https://github.com/pypa/wheel/blob/8dfef1355a8f19e773a08630613bd2da6c636c37/src/wheel/wheelfile.py#L47
    return

  try:
    unpack.unpack(wheel_path)
  except WheelError:
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
