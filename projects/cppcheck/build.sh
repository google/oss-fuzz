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

# build fuzzer

cd $SRC/cppcheck/oss-fuzz

# Build fuzzers
make -j$(nproc) oss-fuzz-client oss-fuzz-client-cfg oss-fuzz-client-cli \
    oss-fuzz-client-project oss-fuzz-client-raw
cp oss-fuzz-client-* $OUT/

# Prepare seed corpus
zip -j -q $OUT/oss-fuzz-client-cfg_seed_corpus.zip $SRC/cppcheck/cfg/*.cfg

# Prepare dict
cp $SRC/cppcheck/oss-fuzz/*.dict $OUT/
