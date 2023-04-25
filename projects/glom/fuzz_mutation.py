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

import glom
import json


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)

  try:
    glom.mutation.delete({'a': [{
        'f': 'z'
    }, {'ff', 'zz'}]}, fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 1024)))
  except (glom.GlomError, ValueError):
    pass

  # Create a random object using json
  try:
    json_val = json.loads(fdp.ConsumeString(fdp.ConsumeIntInRange(0, 1024)))
  except Exception:
    return

  try:
    glom.mutation.delete(json_val, 'a.1.b.2.c')
  except (glom.GlomError, ValueError, TypeError):
    pass

  try:
    glom.mutation.delete(json_val, fdp.ConsumeUnicodeNoSurrogates(64))
  except (glom.GlomError, ValueError, TypeError):
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
