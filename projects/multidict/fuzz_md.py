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

import json
import pickle
import multidict


def run_operation(md, fdp, operation):
  if operation == 1:
    try:
      md.popall(fdp.ConsumeUnicodeNoSurrogates(24))
    except KeyError:
      pass
  elif operation == 2:
    try:
      md.popitem()
    except KeyError:
      pass
  elif operation == 3:
    try:
      md.copy()
    except KeyError:
      pass
  elif operation == 4:
    try:
      md.__delitem__(fdp.ConsumeUnicodeNoSurrogates(24))
    except KeyError:
      pass
  elif operation == 5:
    md[fdp.ConsumeUnicodeNoSurrogates(24)] = fdp.ConsumeUnicodeNoSurrogates(
        24)
    MP = multidict._multidict_py.MultiDictProxy(md)
    MP.copy()
  elif operation == 6:
    try:
      copymd = md.copy()
      is_eq = copymd == md
      copymd['a'] = 2
      is_eq = copymd == md
    except KeyError:
      pass
  elif operation == 7:
    try:
      md.popone(fdp.ConsumeUnicodeNoSurrogates(24))
    except KeyError:
      pass
  elif operation == 8:
    try:
      copymd = md.copy()
      copymd['b'] = 'c'
      md.update(copymd)
    except KeyError:
      pass
  elif operation == 9:
    c2 = multidict._multidict_py.CIMultiDict(md.copy())
  elif operation == 10:
    try:
      md.getall(fdp.ConsumeUnicodeNoSurrogates(24))
    except KeyError:
      pass
  elif operation == 11:
    try:
      md.getone(fdp.ConsumeUnicodeNoSurrogates(24))
    except KeyError:
      pass
  elif operation == 12:
    for elem in md:
      pass
  elif operation == 13:
    len(md)
  elif operation == 14:
    value_view = md.values()
  elif operation == 15:
    representation = str(md)

def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  try:
    random_dict = json.loads(fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 1024)))
  except:
    return
  if not isinstance(random_dict, dict):
    return

  md = multidict._multidict_py.MultiDict(random_dict)
  r = pickle.loads(pickle.dumps(md))

  md = multidict._multidict_py.MultiDict(random_dict)
  # Run one of all operations
  run_operation(md, fdp, 1)
  run_operation(md, fdp, 2)
  run_operation(md, fdp, 3)
  run_operation(md, fdp, 4)
  run_operation(md, fdp, 5)
  run_operation(md, fdp, 6)
  run_operation(md, fdp, 7)
  run_operation(md, fdp, 8)
  run_operation(md, fdp, 9)
  run_operation(md, fdp, 10)
  run_operation(md, fdp, 11)
  run_operation(md, fdp, 12)
  run_operation(md, fdp, 13)
  run_operation(md, fdp, 14)
  run_operation(md, fdp, 15)

  # Run a random sequence of operations
  for idx in range(30):
    operation = fdp.ConsumeIntInRange(1, 15)
    run_operation(md, fdp, operation)


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
