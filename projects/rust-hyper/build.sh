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

cd fuzz

RUSTFLAGS="" cargo build
./target/debug/cli list-targets | while read t; do
    if [ "$FUZZING_ENGINE" = honggfuzz ]; then
        CFLAGS="" CXXFLAGS="" ./target/debug/cli build $t --fuzzer $FUZZING_ENGINE
    fi
    if [ "$FUZZING_ENGINE" = afl ]; then
        CC=clang CXX=clang++ RUSTFLAGS="" ./target/debug/cli build $t --fuzzer $FUZZING_ENGINE
    fi
    if [ "$FUZZING_ENGINE" = libfuzzer ]; then
        ./target/debug/cli build $t --fuzzer $FUZZING_ENGINE
    fi
    find target/ -name $t -type f | while read i; do cp $i $OUT/fuzz_$t; done
done
