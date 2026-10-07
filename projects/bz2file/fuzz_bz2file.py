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
import atheris

import bz2file


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  bzfile_path = '/tmp/random_file.txt'
  with open(bzfile_path, 'wb') as f:
    f.write(fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 2048)))

  try:
    with bz2file.open(bzfile_path) as target_file:
      target_file.seek(fdp.ConsumeIntInRange(-1, 100))
      target_file.read(size=fdp.ConsumeIntInRange(-1, 100))
  except (ValueError,EOFError,OSError):
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
