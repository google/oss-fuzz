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

mv -f ./tests/korean.* $OUT/
mv -f ./tests/utf8_nonbmp.* $OUT/

autoreconf -vfi
./configure --disable-shared --enable-static
make clean
make -j$(nproc) 
$CXX $CXXFLAGS -o $OUT/fuzzer -I./src/ $LIB_FUZZING_ENGINE ./src/tools/fuzzer.cxx ./src/hunspell/.libs/libhunspell-1.7.a
