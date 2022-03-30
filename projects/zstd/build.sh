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


cd tests/fuzz

# Download the seed corpora
make -j seedcorpora
# Build all of the fuzzers
./fuzz.py build all

for target in $(./fuzz.py list); do
    cp "$target" "$OUT"

    if [ -f "$target.dict" ]; then
        cp "$target.dict" "$OUT"
    fi

    cp "corpora/${target}_seed_corpus.zip" "$OUT"
done
