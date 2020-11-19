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
"""This fuzzer is an example of native extension fuzzing with coverage.

This requires that the fuzzer be built with coverage:
see build_install_ujson.sh.
The fuzzer should then be executed under ASAN.

As an example, this is the run command under the author's machine:
    LD_PRELOAD="/usr/lib/llvm-9/lib/clang/9.0.1/lib/linux/libclang_rt.asan-x86_64.so
    $(python3 -c "import atheris; print(atheris.path())")" python3
    ./ujson_fuzzer.py -detect_leaks=0

This fuzzer is provided mainly as an example for how to deal with native
coverage.
"""

import sys
import atheris
import ujson


def TestOneInput(input_bytes):
  fdp = atheris.FuzzedDataProvider(input_bytes)
  original = fdp.ConsumeUnicode(sys.maxsize)

  try:
    ujson_data = ujson.loads(original)
  except ValueError:
    return

  # We make sure there's no error in encoding, but we don't actually compare
  # (encoded == original) because it's not entirely preserving. For example,
  # it does not preserve whitespace.
  encoded = ujson.dumps(ujson_data)
  del encoded


def main():
  # Since everything interesting in this fuzzer is in native code, we can
  # disable Python coverage to improve performance and reduce coverage noise.
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=False)
  atheris.Fuzz()

if __name__ == "__main__":
  main()
