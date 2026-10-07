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

# LODEPNG_MAX_ALLOC flag lets the decoder gracefully return error when trying to
# allocate more than 100MB memory, which prevents OOM with the 2GB limit.
$CXX $CXXFLAGS -DLODEPNG_MAX_ALLOC=100000000 lodepng.cpp lodepng_fuzzer.cpp -o\
 $OUT/lodepng_fuzzer $LIB_FUZZING_ENGINE

# copy seed corpus
cp $SRC/lodepng_fuzzer_seed_corpus.zip $OUT/

# copy dictionary file
cp $SRC/*.dict $OUT/
