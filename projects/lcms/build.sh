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

# build the target.
./configure --enable-shared=no
make -j$(nproc) all

# build your fuzzer(s)
FUZZERS="cmsIT8_load_fuzzer cms_transform_fuzzer cms_overwrite_transform_fuzzer cms_transform_all_fuzzer"
for F in $FUZZERS; do
    $CC $CFLAGS -c -Iinclude \
        $SRC/$F.c -o $SRC/$F.o
    $CXX $CXXFLAGS \
        $SRC/$F.o -o $OUT/$F \
        $LIB_FUZZING_ENGINE src/.libs/liblcms2.a
done

cp $SRC/icc.dict $SRC/*.options $OUT/
