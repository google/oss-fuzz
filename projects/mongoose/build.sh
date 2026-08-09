#!/bin/bash -eu
# Copyright 2020 Google LLC
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

cd $SRC/mongoose
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -I. test/fuzz.c -o $OUT/fuzz

# Fuzzer using honggfuzz netdriver.
if [[ "$FUZZING_ENGINE" == "honggfuzz" ]]
then
 $CC $LIB_FUZZING_ENGINE $CFLAGS -DMG_ENABLE_LINES=1 \
   -DMG_DISABLE_DAV_AUTH -DMG_ENABLE_FAKE_DAVLOCK \
   $LIB_HFND "$HFND_CFLAGS" \
   fuzz_netdriver_http.c mongoose.c -I. -o $OUT/fuzz_netdriver_http  \
   -pthread
fi
