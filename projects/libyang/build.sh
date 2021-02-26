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

for fuzzer in lyd_parse_mem_json lyd_parse_mem_xml lys_parse_mem; do
    $CC $CFLAGS $LIB_FUZZING_ENGINE ../tests/fuzz/${fuzzer}.c -o $OUT/${fuzzer} \
        ./libyang.a -I../src -I./src -I./compat ${static_pcre} 
done
