#!/bin/bash -eux
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


# build project
export ASAN_OPTIONS=detect_leaks=0
./autogen.sh
./configure --disable-shared --with-speechplayer=no
make -j$(nproc)

# Build the ssml-fuzzer manually with $LIB_FUZZING_ENGINE
$CC $CFLAGS -I. -Isrc/include -c tests/ssml-fuzzer.c -o tests/ssml-fuzzer.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE tests/ssml-fuzzer.o \
    src/.libs/libespeak-ng.a -o $OUT/ssml-fuzzer -lm

# Build the synth_fuzzer manually with $LIB_FUZZING_ENGINE
# Instruct the synth_fuzzer to use "en" for FUZZ_VOICE. We do not set
# the environment variable at runtime, so we conver https://github.com/espeak-ng/espeak-ng/blob/3dcbe7ea3ea85a9212968d0f05172dde4259e770/tests/fuzzing/synth_fuzzer.c#L54C22-L54C28
# to const char *lang = "en";//getenv("FUZZ_VOICE");
sed -i 's/getenv/"en";\/\//g' tests/fuzzing/synth_fuzzer.c
$CC $CFLAGS -I. -Isrc/include -DPATH_ESPEAK_DATA=\"/out/espeak-ng-data\" -Isrc/libespeak-ng \
    -c tests/fuzzing/synth_fuzzer.c -o tests/fuzzing/synth_fuzzer.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE tests/fuzzing/synth_fuzzer.o \
    src/.libs/libespeak-ng.a -o $OUT/synth_fuzzer -lm

cp -r espeak-ng-data/ $OUT/
