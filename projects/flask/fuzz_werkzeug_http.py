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

with atheris.instrument_imports():
  import werkzeug.http as whttp


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  try:
    whttp.parse_content_range_header(fdp.ConsumeUnicode(100))
    whttp.parse_range_header(fdp.ConsumeUnicode(100))
    whttp.parse_set_header(fdp.ConsumeUnicode(100))
    whttp.parse_etags(fdp.ConsumeUnicode(100))
    whttp.parse_if_range_header(fdp.ConsumeUnicode(100))
    whttp.parse_dict_header(fdp.ConsumeUnicode(100))
  except ValueError as e:
    if "Bad range provided" in str(e):
      # https://github.com/pallets/werkzeug/blob/main/src/werkzeug/datastructures.py#L2580
      # https://github.com/pallets/werkzeug/blob/main/src/werkzeug/datastructures.py#L2596
      pass
    else:
      raise e


def main():
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
