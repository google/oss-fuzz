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

with atheris.instrument_imports():
  import json
  from pip._internal.models.direct_url import (
    ArchiveInfo,
    DirectUrl,
    DirectUrlValidationError
  )


@atheris.instrument_func
def TestOneInput(input_bytes):
  fdp = atheris.FuzzedDataProvider(input_bytes)

  s1 = fdp.ConsumeUnicode(200)
  try:
    json_string = json.loads(s1)
    if not type(json_string) is dict:
      return
  except json.JSONDecodeError:
    return

  try: 
    direct_url = DirectUrl.from_json(s1)
  except DirectUrlValidationError as e:
    None


def main():
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
