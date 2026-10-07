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

git submodule update --init --recursive

mkdir usr
export CRC32C_INSTALL_PREFIX=$(pwd)/usr

mkdir google_crc32c/build
cd google_crc32c/build
cmake \
  -DCMAKE_BUILD_TYPE=Release \
  -DCRC32C_BUILD_TESTS=no \
  -DCRC32C_BUILD_BENCHMARKS=no \
  -DBUILD_SHARED_LIBS=yes \
  -DCMAKE_INSTALL_PREFIX:PATH=${CRC32C_INSTALL_PREFIX} \
  ../
make all install
cd ../../


python3 setup.py build_ext \
  --include-dirs=$(pwd)/usr/include \
  --library-dirs=$(pwd)/usr/lib \
  --rpath=$(pwd)/usr/lib
pip3 install -e .[testing]

# Build fuzzers in $OUT.
for fuzzer in $(find $SRC -name 'fuzz_*.py'); do
  compile_python_fuzzer $fuzzer
done
