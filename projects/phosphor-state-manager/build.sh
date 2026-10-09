#!/bin/bash -eu
# Copyright 2026 Google LLC
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

$CXX $CXXFLAGS -std=c++23 -I$SRC/phosphor-state-manager -I$SRC/mock_includes \
    $SRC/target_parser_fuzzer.cpp \
    $SRC/phosphor-state-manager/systemd_target_parser.cpp \
    -o $OUT/target_parser_fuzzer \
    $LIB_FUZZING_ENGINE

# Copy dictionary
cp $SRC/target_parser_fuzzer.dict $OUT/

# Create seed corpus
zip -q -j $OUT/target_parser_fuzzer_seed_corpus.zip \
    $SRC/phosphor-state-manager/data/phosphor-target-monitor-default.json
