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

from typing_extensions import (TypeVarTuple, Unpack, dataclass_transform,
                               TypedDict)


def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  s1 = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 1024))
  s2 = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 1024))
  Tvt = TypeVarTuple(s1)
  Tvt2 = TypeVarTuple(s2)
  hash(Tvt)
  list(Tvt)
  repr(Tvt)

  if s1 != s2:
    try:
      assert Unpack[Tvt] != Unpack[Tvt2]
    except (SyntaxError, ValueError):
      pass
    try:
      assert Unpack[s1] != Unpack[s2]
    except (SyntaxError, ValueError):
      pass

  try:
    d1 = json.loads(
        fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 256)))
    d2 = json.loads(
        fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 256)))
  except:
    d1 = None
    d2 = None
  if isinstance(d1, dict) and isinsance(d2, dict):
    if d1 != d2:
      assert TypedDict('D1', d1) != TypedDict('D2', d2)
    else:
      assert TypedDict('D1', d1) == TypedDict('D2', d2)

  dataclass_transform(eq_default=fdp.ConsumeBool(),
                      order_default=fdp.ConsumeBool(),
                      kw_only_default=fdp.ConsumeBool(),
                      frozen_default=fdp.ConsumeBool(),
                      kwargs={})


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
