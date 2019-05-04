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

# target_dir determined by Dockerfile
target_dir="$SRC/fuzz-targets"

# build wolfssl
./autogen.sh
./configure --enable-static --disable-shared --prefix=/usr CC="clang"
make -j "$(nproc)" all
make install

# put linker arguments into the environment, appending to any existing ones
export LDFLAGS="${LDFLAGS-""}"
export LDLIBS="${LDLIBS-""} -lwolfssl $LIB_FUZZING_ENGINE"

# make and export targets to $OUT; environment overridding internal variables
cd "${target_dir}"
make -e all
make -e export prefix="$OUT"
