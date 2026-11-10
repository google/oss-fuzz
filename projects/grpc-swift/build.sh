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

. precompile_swift
# build project
cd FuzzTesting

EXTRA_LINKER_FLAGS=""
for lib in libc++.a libc++abi.a libunwind.a; do
    lib_path=$(find /usr/local/lib /usr/lib -name "$lib" 2>/dev/null | head -n 1)
    if [ -n "$lib_path" ]; then
        EXTRA_LINKER_FLAGS="$EXTRA_LINKER_FLAGS -Xlinker $lib_path"
    fi
done

swift build -c debug $SWIFTFLAGS $EXTRA_LINKER_FLAGS

(
cd .build/debug/
find . -maxdepth 1 -type f -name "*Fuzzer" -executable | while read i; do cp $i $OUT/"$i"-debug; done
)
swift build -c release $SWIFTFLAGS $EXTRA_LINKER_FLAGS
(
cd .build/release/
find . -maxdepth 1 -type f -name "*Fuzzer" -executable | while read i; do cp $i $OUT/"$i"-release; done
)
