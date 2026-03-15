# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS.

#!/bin/bash -eu


cd "$SRC/weavebundle"

cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DWEAVEBUNDLE_ENABLE_FUZZING=ON

cmake --build build --target fuzz_parser

cp build/fuzz_parser "$OUT/"

mkdir -p $OUT/fuzz_parser_seed_corpus
cp examples/*.wvbf $OUT/fuzz_parser_seed_corpus/