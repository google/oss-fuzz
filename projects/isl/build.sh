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

./autogen.sh
sed -i 's/CFLAGS="-O3"/CFLAGS="-O3 ${OSS_FLAGS}"/g' ./configure
export OSS_FLAGS="${CFLAGS}"
./configure
make V=1

for fuzzname in union; do
  $CC $CFLAGS $LIB_FUZZING_ENGINE -I./include $SRC/fuzz_${fuzzname}.c -o $OUT/fuzz_${fuzzname} ./.libs/libisl.a  -lgmp
done

cp $SRC/fuzz_union.options $OUT/fuzz_union.options
