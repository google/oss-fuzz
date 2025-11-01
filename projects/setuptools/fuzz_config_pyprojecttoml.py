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

import sys
import os
import tempfile
import atheris

with atheris.instrument_imports():
    import tomli
    from setuptools.config.pyprojecttoml import (read_configuration)
    from setuptools.errors import FileError


def TestOneInput(data):
  """Fuzzer read_configuration assuming any valid toml file should not
  cause exceptions to happen.
  """
  fdp = atheris.FuzzedDataProvider(data)
  with tempfile.TemporaryDirectory() as temp_dir:
    config_path = os.path.join(temp_dir, "pyproject.taml")
    with open(config_path, "w") as cf:
      cf.write(fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 4096)))

  try:
    config = read_configuration(config_path)
  except (tomli.TOMLDecodeError, FileError):
    return -1


def main():
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
