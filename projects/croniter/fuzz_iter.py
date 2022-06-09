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

from datetime import datetime

with atheris.instrument_imports():
  from croniter import (
    croniter,
    CroniterBadCronError,
    CroniterBadDateError
  )


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  base = datetime(2012, 4, 6, 13, 26, 10)
  try:
    itr = croniter(fdp.ConsumeString(50), base)
    idx = 0
    for v in itr.all_next():
      idx += 1
      if idx > 10:
        break
  except (CroniterBadCronError, CroniterBadDateError) as e:
    pass
  except NameError as e:
    # Catch https://github.com/kiorky/croniter/blob/bb5a45196e5f8f15fd0890f4ee5e9697671a3fe2/src/croniter/croniter.py#L781
    if not "'exc' is not defined" in str(e):
      raise e


def main():
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()

if __name__ == "__main__":
  main()
