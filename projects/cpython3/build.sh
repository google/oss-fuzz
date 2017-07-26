#!/bin/bash -eu
# Copyright 2017 Google Inc.
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

# Workaround for distutils, which doesn't copy $CC except on OSX.
export LDSHARED="$CC -shared"
# Workaround for PGen, which doesn't use CFLAGS for linking
export LDFLAGS="$CFLAGS"
# _freeze_importlib, and presumably all other binaries (including the fuzzer),
# trip the leak detection.
export ASAN_OPTIONS="detect_leaks=0"

# Build python to run the app.
pushd cpython
./configure --prefix=$OUT/ --with-ensurepip=no
make -j$(nproc) install
popd

FUZZ_DIR=cpython/Modules/_fuzz
for fuzz_test in $(cat $FUZZ_DIR/fuzz_tests.txt)
do
  $CXX $CXXFLAGS \
    -D _Py_FUZZ_ONE -D _Py_FUZZ_$fuzz_test \
    -Wno-unused-function \
    $($OUT/bin/python3-config --cflags) -g -O1 \
    $FUZZ_DIR/fuzzer.cpp -o $OUT/$fuzz_test -lFuzzingEngine \
    $($OUT/bin/python3-config --ldflags)
done

