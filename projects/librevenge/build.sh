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

CXX="$CXX -std=c++11 -stdlib=libc++"

./autogen.sh
./configure --without-docs --disable-shared --enable-static --disable-tests --disable-generators --enable-fuzzers
make -j$(nproc)

cp src/fuzz/*fuzzer $OUT
cp $SRC/*_seed_corpus.zip $OUT
