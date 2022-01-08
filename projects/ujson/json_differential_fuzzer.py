#!/usr/bin/python3

# Copyright 2020 Google LLC
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
""" An example native JSON vs uJSON differential fuzzer.

This fuzzer looks for differences between the built-in json library and the
native ujson library. The ujson library should be built for coverage (see
build_install_ujson.sh), and the Python fuzzer should be executed under ASAN.
As an example:
    LD_PRELOAD="/usr/lib/llvm-9/lib/clang/9.0.1/lib/linux/libclang_rt.asan-x86_64.so
    $(python3 -c "import atheris; print(atheris.path())")" python3
    ./json_differential_fuzzer.py -detect_leaks=0

This fuzzer has found a bug with inconsistent handling of integers with
too-high magnitude. uJSON sometimes refuses to process numbers that are too far
from 0 with "Value is too big!" or the equivalent for values that are too
negative. However, other times it happily processes them with two's compliment
mod. As an example, it refuses to parse "-9223372036854775809" (the first
integer not representable in a 64-bit signed number) with "Value is too small";
but it will happily parse "-80888888888888888888", a significantly more negative
number. However, it parses it as -9223372036854775808. The JSON spec
(https://tools.ietf.org/html/rfc7159#section-6) "allows implementations to set
limits on the range and precision of numbers accepted", so failing to parse
values that are too big or too small is techincally fine; however,
misinterpreting them is not.
"""

import atheris
import sys

with atheris.instrument_imports():
  import json
  import ujson


@atheris.instrument_func
def ClearAllIntegers(data):
  """Used to prevent known bug; sets all integers in data recursively to 0."""
  if type(data) == int:
    return 0
  if type(data) == list:
    for i in range(0, len(data)):
      data[i] = ClearAllIntegers(data[i])
  if type(data) == dict:
    for k, v in data:
      data[k] = ClearAllIntegers(v)
  return data


@atheris.instrument_func
def TestOneInput(input_bytes):
  fdp = atheris.FuzzedDataProvider(input_bytes)
  original = fdp.ConsumeUnicode(sys.maxsize)

  try:
    ujson_data = ujson.loads(original)
    json_data = json.loads(original)
  except Exception as e:
    # It would be interesting to enforce that if one of the libraries throws an
    # exception, the other does too. However, uJSON accepts many invalid inputs
    # that are uninteresting, such as "00". So, that is not done.
    return

  # Uncomment these lines to ignore the errors described in the docstring of
  # this file.
  # json_data = ClearAllIntegers(json_data)
  # ujson_data = ClearAllIntegers(ujson_data)

  json_dumped = json.dumps(json_data)
  ujson_dumped = json.dumps(ujson_data)

  if json_dumped != ujson_dumped:
    raise RuntimeError(
        "Decoding/encoding disagreement!\nInput: %s\nJSON data: %s\nuJSON data: %s\nJSON-dumped: %s\nuJSON-dumped: %s\n"
        % (original, json_data, ujson_data, json_dumped, ujson_dumped))


def main():
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()
