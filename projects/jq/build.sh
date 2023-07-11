#!/bin/bash -eu
#
# Copyright 2023 Google LLC
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

git submodule init
git submodule update
autoreconf -fi
./configure --with-oniguruma=builtin
make -j$(nproc)

$CC $CFLAGS -c tests/jq_fuzz_parse.c \
    -I./src -o ./jq_fuzz_parse.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ./jq_fuzz_parse.o \
    ./.libs/libjq.a ./modules/oniguruma/src/.libs/libonig.a \
    -o $OUT/jq_fuzz_parse -I./src
