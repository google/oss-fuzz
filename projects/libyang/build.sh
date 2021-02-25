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
cd libyang
git checkout libyang2

sed -i 's/add_subdirectory/#add_subdirectory/g' ./tools/CMakeLists.txt
mkdir build && cd build
cmake ../ -DENABLE_STATIC=ON 
make

static_pcre=($(find /src/pcre2 -name "libpcre2-8.a"))

for fuzzer in lyd_parse_mem_json lyd_parse_mem_xml lys_parse_mem yang_parse_module; do
    $CC $CFLAGS $LIB_FUZZING_ENGINE ../tests/fuzz/${fuzzer}.c -o $OUT/${fuzzer} \
        ./libyang.a -I../src -I./src -I./compat ${static_pcre} 
done
#$CC $CFLAGS $LIB_FUZZING_ENGINE ../tests/fuzz/lyd_parse_mem_json.c -o $OUT/lyd_parse_mem_json ./libyang.a -I../src -I./src ${static_pcre}
#$CC $CFLAGS $LIB_FUZZING_ENGINE ../tests/fuzz/lyd_parse_mem_xml.c -o $OUT/lyd_parse_mem_xml ./libyang.a -I../src -I./src ${static_pcre}
#$CC $CFLAGS $LIB_FUZZING_ENGINE ../tests/fuzz/lys_parse_mem.c -o $OUT/lys_parse_mem ./libyang.a -I../src -I./src ${static_pcre}

#mkdir build && cd build
#cmake ../ -DENABLE_STATIC=ON 
#make

# Fuzz
#cp $SRC/fuzz_yang.c .
#$CC $CFLAGS $LIB_FUZZING_ENGINE fuzz_yang.c -o $OUT/fuzz_yan \
#    libyang.a libyangdata.a libuser_inet_types.a libmetadata.a \
#    libuser_yang_types.a libnacm.a -I./src -I../src -lpcre
