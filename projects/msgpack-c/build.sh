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

for f in $SRC/msgpack-c/fuzz/*_fuzzer.cpp; do
    # NOTE(derwolfe): the naming scheme for fuzzers and seed corpora is
    # fuzzer = something_something_fuzzer.cpp
    # seed corpus = something_something_fuzzer_seed_corpus
    fuzzer=$(basename "$f" .cpp)
    $CXX $CXXFLAGS -std=c++11 -Iinclude -I"$SRC/msgpack-c/include" \
         "$f" -o "$OUT/${fuzzer}" \
         $LIB_FUZZING_ENGINE

    if [ -d "$SRC/msgpack-c/fuzz/${fuzzer}_seed_corpus" ]; then
        zip -rj "$OUT/${fuzzer}_seed_corpus.zip" "$SRC/msgpack-c/fuzz/${fuzzer}_seed_corpus/"
    fi
done
