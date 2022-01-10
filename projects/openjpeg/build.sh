#!/bin/bash -eu
# Copyright 2017 Google Inc.
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

# Get data. We do this here to resolve CIFuzz issues
# CC https://github.com/uclouvain/openjpeg/pull/1386
git clone --depth 1 https://github.com/uclouvain/openjpeg-data data

mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make clean -s
make -j$(nproc) -s
cd ..

./tests/fuzzers/build_google_oss_fuzzers.sh
./tests/fuzzers/build_seed_corpus.sh
