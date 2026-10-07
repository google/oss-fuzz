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
import json
import atheris

import jsonschema
import openapi_schema_validator


def gen_random_dict(data):
  """Generates a simple random dictionary where values can either be strings or
  dictionaries (where the values there are strings."""
  fdp = atheris.FuzzedDataProvider(data)
  fuzz_dict = dict()
  for idx in range(fdp.ConsumeIntInRange(1, 30)):
    key = fdp.ConsumeUnicodeNoSurrogates(40)
    if fdp.ConsumeBool():
      val_dict = dict()
      for idx2 in range(fdp.ConsumeIntInRange(2, 30)):
        val_dict[fdp.ConsumeUnicodeNoSurrogates(
            40)] = fdp.ConsumeUnicodeNoSurrogates(40)
      fuzz_dict[key] = val_dict
    else:
      fuzz_dict[key] = fdp.ConsumeUnicodeNoSurrogates(40)
  return fuzz_dict


def TestOneInput(data):
  fuzz_dict_instance = gen_random_dict(data)
  fuzz_dict_schema = gen_random_dict(data)
  try:
    openapi_schema_validator.validate(fuzz_dict_instance, fuzz_dict_schema)
  except (jsonschema.exceptions._Error):
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
