#!/bin/bash -eu
# Copyright 2024 Google LLC
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

# build project
mkdir build
pushd build
cmake -DARCH=x64 -DTOOLCHAIN=LIBFUZZER -DTARGET=Release -DCRYPTO=mbedtls -DGCOV=ON ..
make copy_sample_key -j$(nproc)
make -j$(nproc)
cp -r ./bin/* $OUT
popd

# build unit testing that requires different TOOLCHAIN
# Unset CFLAGS that incompatible with unit testing build
unset CFLAGS
mkdir build-test
pushd build-test
cmake -DARCH=x64 -DTOOLCHAIN="CLANG" -DTARGET=Release -DCRYPTO=mbedtls ..
make -j$(nproc)
popd

# Prepare sample key and unit testing binary
mkdir $SRC/unit_testing
cp -r $SRC/libspdm/unit_test/sample_key/* $SRC/unit_testing/
cp $SRC/libspdm/build-test/bin/* $SRC/unit_testing/
