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
import atheris

import aniso8601
from aniso8601.date import parse_date
from aniso8601.decimalfraction import normalize
from aniso8601.duration import parse_duration
from aniso8601.interval import parse_interval
from aniso8601.timezone import parse_timezone


def fuzz_date(data):
  fdp = atheris.FuzzedDataProvider(data)
  try:
    parse_date(fdp.ConsumeUnicodeNoSurrogates(sys.maxsize))
  except (aniso8601.exceptions.ISOFormatError,
          aniso8601.exceptions.RangeCheckError):
    pass
  except NotImplementedError:
    # https://bitbucket.org/nielsenb/aniso8601/src/8819c46cb9548298da5b59b830782c1cc37ba295/aniso8601/date.py#lines-77
    pass


def fuzz_decimal_fraction(data):
  fdp = atheris.FuzzedDataProvider(data)
  normalize(fdp.ConsumeUnicodeNoSurrogates(sys.maxsize))


def fuzz_duration(data):
  fdp = atheris.FuzzedDataProvider(data)
  try:
    parse_duration(fdp.ConsumeUnicodeNoSurrogates(sys.maxsize))
  except (aniso8601.exceptions.ISOFormatError,
          aniso8601.exceptions.RangeCheckError):
    pass
  except NotImplementedError:
    # https://bitbucket.org/nielsenb/aniso8601/src/8819c46cb9548298da5b59b830782c1cc37ba295/aniso8601/date.py#lines-77
    pass


def fuzz_interval(data):
  fdp = atheris.FuzzedDataProvider(data)
  try:
    parse_interval(fdp.ConsumeUnicodeNoSurrogates(sys.maxsize))
  except (aniso8601.exceptions.ISOFormatError,
          aniso8601.exceptions.RangeCheckError):
    pass
  except NotImplementedError:
    # https://bitbucket.org/nielsenb/aniso8601/src/8819c46cb9548298da5b59b830782c1cc37ba295/aniso8601/date.py#lines-77
    pass


def fuzz_time(data):
  fdp = atheris.FuzzedDataProvider(data)
  try:
    parse_timezone(fdp.ConsumeUnicodeNoSurrogates(sys.maxsize))
  except (aniso8601.exceptions.ISOFormatError,
          aniso8601.exceptions.RangeCheckError):
    pass
  except NotImplementedError:
    # https://bitbucket.org/nielsenb/aniso8601/src/8819c46cb9548298da5b59b830782c1cc37ba295/aniso8601/date.py#lines-77
    pass


def TestOneInput(data):
  fuzz_date(data)
  fuzz_decimal_fraction(data)
  fuzz_duration(data)
  fuzz_interval(data)
  fuzz_time(data)


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
