#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

# Build Jerryscript
python tools/build.py \
        --linker-flag '${CXX} ${CXXFLAGS}' \
        --compile-flag '${CXX} ${CXXFLAGS}' \
        --lto 'OFF' \
        --libfuzzer 'OFF'
cd $SRC/jerryscript


# Build fuzzer
sed 's/int LLVMFuzzerTestOneInput/extern "C" int LLVMFuzzerTestOneInput/g' -i jerry-main/libfuzzer.c
$CXX $CXXFLAGS \
        -I/src/jerryscript/jerry-core/include \
        -I/src/jerryscript/jerry-libm/include \
        -I/src/jerryscript/jerry-port/default/include \
        -c ./jerry-main/libfuzzer.c \
        -o libfuzzer.o


$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
        libfuzzer.o -o $OUT/jerry_fuzzer \
        ./build/lib/libjerry-core.a \
        ./build/lib/libjerry-port-default.a \
        ./build/lib/libjerry-core.a \
        ./build/lib/libjerry-libm.a
