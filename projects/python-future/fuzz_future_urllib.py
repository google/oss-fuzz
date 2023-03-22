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

import future.backports.urllib.request as urllib_request
from future.backports.urllib import parse as urllib_parse


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  str_list = []
  for i in range(5):
    str_list.append(
        fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 1024)))
  urllib_request.parse_http_list(str_list)

  # urllib_parse
  try:
    urllib_parse.quote(
        fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 1024)),
        encoding=fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 16)),
        safe=fdp.ConsumeUnicodeNoSurrogates(2))
  except (LookupError, TypeError, ValueError):
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
