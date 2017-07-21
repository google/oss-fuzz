#!/bin/bash -eu
# Copyright 2016 Google Inc.
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
export LDSHARED="clang -shared"
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
for fuzz_test in $(ls $FUZZ_DIR/fuzz_*.inc | egrep -o 'fuzz_[^.]*' )
do
  $OUT/bin/python3 $SRC/gen_fuzz.py $FUZZ_DIR/$fuzz_test.inc $fuzz_test > $FUZZ_DIR/$fuzz_test.cc
  $CXX $CXXFLAGS \
    $($OUT/bin/python3-config --cflags) -g -O1 \
    $FUZZ_DIR/$fuzz_test.cc -o $OUT/$fuzz_test -lFuzzingEngine \
    $($OUT/bin/python3-config --ldflags)
done

