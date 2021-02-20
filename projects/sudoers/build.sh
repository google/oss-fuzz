#!/bin/bash -eu
# Copyright 2021 Google LLC
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

# Debugging
env

# Some of the sanitizer flags cause issues with configure tests.
# Pull them out of CFLAGS and pass them to configure instead.
if [ $SANITIZER == "coverage" ]; then
    CFLAGS="`echo \"$CFLAGS\" | sed \"s/ $COVERAGE_FLAGS//\"`"
    sanitizer_opts="$COVERAGE_FLAGS"
else
    CFLAGS="`echo \"$CFLAGS\" | sed \"s/ $SANITIZER_FLAGS//\"`"
    sanitizer_opts="$SANITIZER_FLAGS"
fi
# This is already added by --enable-fuzzer
CFLAGS="`echo \"$CFLAGS\" | sed \"s/ -fsanitize=fuzzer-no-link//\"`"

# Build sudo with static libs and enable fuzzing targets.
# All fuzz targets are integrated into the build process.
./configure --disable-shared --disable-shared-libutil --enable-static-sudoers \
    --enable-sanitizer="$sanitizer_opts" --enable-fuzzer \
    --enable-fuzzer-engine="$LIB_FUZZING_ENGINE" --enable-fuzzer-linker="$CXX" \
    --enable-warnings --enable-werror
make -j$(nproc) && make FUZZ_DESTDIR=$OUT install-fuzzer
