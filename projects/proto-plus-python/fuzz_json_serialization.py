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

import proto
from google.protobuf.json_format import ParseError

def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)

  class FuzzMsg(proto.Message):
    val1 = proto.Field(proto.FLOAT, number=1)
    val2 = proto.Field(proto.INT32, number=2)
    val3 = proto.Field(proto.BOOL, number=3)
    val4 = proto.Field(proto.STRING, number=4)

  try:
    s = FuzzMsg.from_json(fdp.ConsumeUnicodeNoSurrogates(sys.maxsize))
    FuzzMsg.to_json(s)
  except ParseError:
    pass
  except TypeError:
    pass
  except RecursionError:
    pass


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()


if __name__ == "__main__":
  main()

