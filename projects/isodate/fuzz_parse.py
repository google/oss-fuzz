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

import isodate


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  try:
    isodate.isodates.parse_date(fdp.ConsumeUnicodeNoSurrogates(1024))
  except (
    # parse_date can legitimately raise two types of exceptions:
    # https://github.com/gweis/isodate/blob/8856fdf0e46c7bca00229faa1aae6b7e8ad6e76c/src/isodate/isodates.py#L150-L151
    isodate.ISO8601Error,
    ValueError,
  ):
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
