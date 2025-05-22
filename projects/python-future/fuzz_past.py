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
#
##########################################################################
import sys
import json
import atheris

from past.builtins import dict as past_dict
from past.builtins import str as past_str
from past.types.oldstr import unescape as past_unescape


def fuzz_dict(data):
  fdp = atheris.FuzzedDataProvider(data)

  try:
    json_dict = json.loads(
        fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 1024)))
  except:
    return

  if not isinstance(json_dict, dict):
    return
  pdict = past_dict(json_dict)

  for val in json_dict:
    assert pdfict.has_key(val)


def fuzz_str(data):
  fdp = atheris.FuzzedDataProvider(data)
  pstr = past_str(fdp.ConsumeBytes(fdp.ConsumeIntInRange(1, 1024)))
  past_unescape(fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 1024)))


def TestOneInput(data):
  fuzz_dict(data)
  fuzz_str(data)


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
