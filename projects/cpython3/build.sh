#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

# Both configure and make execute programs that return non-zero exit codes due
# to leaks.
export ASAN_OPTIONS=detect_leaks=0
./configure --without-pymalloc --disable-shared --prefix=$OUT LINKCC="$CXX" \
  LDFLAGS="$CXXFLAGS"
make -j$(nproc) && make install

for test in $(cat Modules/_xxtestfuzz/fuzz_tests.txt)
do
$CC -D _Py_FUZZ_ONE -D _Py_FUZZ_$test $CXXFLAGS Modules/_xxtestfuzz/fuzzer.c \
  $OUT/lib/libpython3.8.a $($OUT/bin/python3-config --includes) -ldl -lutil \
  -lm -lFuzzingEngine -lc++ -o $OUT/$test
done
