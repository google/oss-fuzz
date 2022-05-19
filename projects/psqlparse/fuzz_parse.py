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
# We import json here although it's not used in this file. This is becaused
# it is needed for the library and pyinstaller forgets it if we don't import
# it here. This is also needed for psqlparse.nodes below
import json
import sys

with atheris.instrument_imports():
  from psqlparse import parse
  from psqlparse.exceptions import PSqlParseError
  import psqlparse.nodes


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  s = fdp.ConsumeString(sys.maxsize)
  try:
    parse(s)
  except PSqlParseError as e:
    None
  except UnicodeEncodeError as e:
    None

def main():
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()

if __name__ == "__main__":
  main()
