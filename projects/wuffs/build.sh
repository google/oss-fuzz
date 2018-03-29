#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

# "Build the project" is a no-op. There is no "./configure.sh && make" dance.
# Wuffs' generated C files are "drop-in libraries" a la
# http://gpfault.net/posts/drop-in-libraries.txt.html

for f in fuzz/c/std/*_fuzzer.cc; do
  b=$(basename $f _fuzzer.cc)
  $CXX $CXXFLAGS -std=c++11 $f -o $OUT/${b}_fuzzer -lFuzzingEngine
  zip --junk-paths $OUT/${b}_fuzzer_seed_corpus.zip test/data/*.$b
done
