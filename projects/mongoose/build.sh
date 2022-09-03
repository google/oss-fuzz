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
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -DMG_ENABLE_LINES -DMG_ENABLE_LOG=0 mongoose.c -I. test/fuzz.c -o $OUT/fuzz

# Fuzzer using honggfuzz netdriver.
if [[ "$FUZZING_ENGINE" == "honggfuzz" ]]
then
  $CC $LIB_FUZZING_ENGINE $CFLAGS $HF_NETDRIVER -DMG_ENABLE_LINES=1 \
    -D "HFND_FUZZING_ENTRY_FUNCTION_CXX(x,y)=extern const char* LIBHFNETDRIVER_module_netdriver;const char** LIBHFNETDRIVER_tmp1 = &LIBHFNETDRIVER_module_netdriver;extern \"C\" int HonggfuzzNetDriver_main(x,y);int HonggfuzzNetDriver_main(x,y)" \
    -D "HFND_FUZZING_ENTRY_FUNCTION(x,y)=extern const char* LIBHFNETDRIVER_module_netdriver;const char** LIBHFNETDRIVER_tmp1 = &LIBHFNETDRIVER_module_netdriver;int HonggfuzzNetDriver_main(x,y);int HonggfuzzNetDriver_main(x,y)" \
    -I /src/honggfuzz/includes/ -D __NO_STRING_INLINES \
    -DMG_DISABLE_DAV_AUTH -DMG_ENABLE_FAKE_DAVLOCK \
    fuzz_netdriver_http.c mongoose.c -I. -o $OUT/fuzz_netdriver_http  \
    -pthread -v
fi
