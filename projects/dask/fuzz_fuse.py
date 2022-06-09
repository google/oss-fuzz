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
import dask
from dask.optimization import (
    fuse,
    fuse_linear,
)
from dask.utils_test import dec, inc, add

def get_fuse_dict(data):
  fdp = atheris.FuzzedDataProvider(data)
  fuse_dict = dict()
  number_of_entries = fdp.ConsumeIntInRange(1, 50)
  operations = [dec, inc, add]

  previous_keys = list()

  key="a"
  fuse_dict[key] = 1
  previous_keys.append(key)

  for i in range(number_of_entries):
    newk=key+str(i)
    val_op = operations[fdp.ConsumeIntInRange(0, 2)]
    val_id = previous_keys[fdp.ConsumeIntInRange(0, len(previous_keys)-1)]

    fuse_dict[newk] = (val_op, val_id)
    previous_keys.append(newk)
  return fuse_dict
  


@atheris.instrument_func
def TestOneInput(data):
  if len(data) < 10:
    return
  fdp = atheris.FuzzedDataProvider(data)
  fuzzed_dict = get_fuse_dict(data)
  if len(fuzzed_dict) == 0:
    return

  if fdp.ConsumeBool():
    fuse(
      fuzzed_dict,
      rename_keys=fdp.ConsumeBool()
    )
  else:
    fuse_linear(
      fuzzed_dict,
      rename_keys=fdp.ConsumeBool()
    )


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
