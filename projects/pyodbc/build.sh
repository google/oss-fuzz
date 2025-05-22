#!/bin/bash -eu
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
#
################################################################################

# Compile the fake odbc driver
clang -Wno-unused-result -Wsign-compare -Wunreachable-code \
      -fwrapv  -Wno-write-strings -fPIC \
      -shared -I/usr/local/include/python3.8 -I$PWD/src  \
      -o $OUT/fuzzodbc.so $SRC/fake_odbc_driver.c

python3 setup.py install
pip3 install .
for fuzzer in $(find $SRC -name 'fuzz_*.py'); do
  LD_PRELOAD=$OUT/sanitizer_with_fuzzer.so ASAN_OPTIONS=detect_leaks=0 compile_python_fuzzer $fuzzer --add-data $OUT/fuzzodbc.so:.
done
