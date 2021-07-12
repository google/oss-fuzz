#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

export LDFLAGS="$CFLAGS"
./bootstrap.sh
./configure --datadir="$OUT" --prefix="$WORK" --disable-shared
make "-j$(nproc)"
make install

$CXX $CXXFLAGS -std=c++11 "-I$WORK/include" ../libpostal_parse_address_fuzzer.cc \
    -o "$OUT/libpostal_parse_address_fuzzer" $LIB_FUZZING_ENGINE "$WORK/lib/libpostal.a"
