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
  spec = glom.matching.Match([{
      'fuzz1': str,
      'fuzz2': str,
      'fuzz3': int,
      'fuzz4': dict
  }])

  # Create a random object using json
  try:
    json_val = json.loads(fdp.ConsumeString(sys.maxsize))
  except Exception:
    return

  try:
    glom.glom(json_val, spec)
  except glom.GlomError:
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
