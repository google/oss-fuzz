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
  import pytz
  from datetime import datetime
  from pytz.exceptions import Error


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)

  try:
    d1 = datetime(
      fdp.ConsumeInt(4),
      fdp.ConsumeInt(4),
      fdp.ConsumeInt(4),
      fdp.ConsumeInt(4),
      fdp.ConsumeInt(4),
      fdp.ConsumeInt(4)
    )
  except: # Catch everything
    return

  s1 = fdp.ConsumeString(sys.maxsize)
  try:
    east2 = pytz.timezone(s1)
    east2.localize(d1)
  except Error as e:
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
