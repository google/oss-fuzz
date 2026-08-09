#!/bin/bash -eu
# Copyright 2024 Google LLC
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

# Compile the fuzzer binary for oss-fuzz infrastructure.
$CC $CFLAGS -c ini.c
$CC $CFLAGS -c inihfuzz.c
$CXX $CFLAGS $LIB_FUZZING_ENGINE inihfuzz.o ini.o -o inihfuzz

# Setup for oss-fuzz infrastructure.
cp inihfuzz $OUT/
zip -r inihfuzz_seed_corpus.zip tests/*.ini
mv inihfuzz_seed_corpus.zip $OUT/
