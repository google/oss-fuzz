#!/bin/bash -eu
# Copyright 2023 Google LLC
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

cargo fuzz build -O
cargo fuzz list | while read i; do
    cp fuzz/target/x86_64-unknown-linux-gnu/release/$i $OUT/

    if [ -d "$SRC/gimli/fuzz/corpus/${i}" ]; then
        zip -rj "$OUT/${i}_seed_corpus.zip" "$SRC/gimli/fuzz/corpus/${i}"
    fi
done
