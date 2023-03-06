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

  val = {'d': {'e': ['f']}}
  try:
    glom.core.glom(val, glom.core.Inspect(fdp.ConsumeUnicodeNoSurrogates(64)))
  except glom.GlomError:
    pass

  try:
    glom.core.glom(
        val,
        glom.core.Coalesce(fdp.ConsumeUnicodeNoSurrogates(32),
                           fdp.ConsumeUnicodeNoSurrogates(32),
                           fdp.ConsumeUnicodeNoSurrogates(32)))
  except glom.GlomError:
    pass
  # Create a random dictionary. In this case if any
  # error happens during random dict creation we just
  # exit.
  try:
    json_dict = json.loads(fdp.ConsumeString(fdp.ConsumeIntInRange(0, 512)))
  except Exception:
    return
  if not isinstance(json_dict, dict):
    return

  # Use random dict as input to glom
  try:
    glom.core.glom(json_dict, fdp.ConsumeString(30))
  except glom.GlomError:
    pass

  try:
    spec = glom.T['a']['b']['c']
    glom.core.glom(json_dict, spec)
  except glom.GlomError:
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
