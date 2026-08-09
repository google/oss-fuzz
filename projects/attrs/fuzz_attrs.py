#!/usr/bin/python3

# Copyright 2025 Google LLC
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
import atheris

import attrs
from string import ascii_letters

def consumeIdentifier(fdp):
    return fdp.ConsumeUnicode(8)

@atheris.instrument_func
def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  clsname = consumeIdentifier(fdp)
  attrcount = fdp.ConsumeIntInRange(0, 12)
  attrnames = [consumeIdentifier(fdp)
               for _ in range(attrcount)]
  attrvalues = [None] * attrcount

  # Create class from attrs.make_class
  try:
    C0 = attrs.make_class(clsname, attrnames)
  except Exception as e:
      if any(not name.isidentifier() for name in [clsname] + attrnames):
          return
      raise
  c0 = C0(**{k: v for k, v in zip(attrnames, attrvalues)})
  d0 = attrs.asdict(c0)
  c0_p = C0(**d0)
  assert c0 == c0_p

  # Create class from attrs.define
  C1 = attrs.define(type(clsname, (), {f: attrs.field() for f in attrnames}))
  c1 = C1(**{k: v for k, v in zip(attrnames, attrvalues)})
  d1 = attrs.asdict(c1)
  c1_p = C1(**d1)
  assert c1 == c1_p


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
