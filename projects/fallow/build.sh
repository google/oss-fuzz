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

cd $SRC/fallow
cargo fuzz build -O --debug-assertions

fuzz_release=$SRC/fallow/fuzz/target/x86_64-unknown-linux-gnu/release
for target in $(cargo fuzz list); do
  cp "$fuzz_release/$target" "$OUT/"
  if [ -f "fuzz/dicts/$target.dict" ]; then
    cp "fuzz/dicts/$target.dict" "$OUT/$target.dict"
  fi
  seeds=(fuzz/corpus/$target/*)
  if [ -e "${seeds[0]}" ]; then
    zip -jq "$OUT/${target}_seed_corpus.zip" "${seeds[@]}"
  fi
done
