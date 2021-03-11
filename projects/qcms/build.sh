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

cargo fuzz build -O

find fuzz -iname "*.icc" \
  -type f -exec zip -qju $OUT/fuzz_seed_corpus.zip "{}" \;
cp fuzz/qcms_fuzzer.dict $OUT/fuzz.dict
cp fuzz/target/x86_64-unknown-linux-gnu/release/fuzz_target_qcms $OUT/fuzz
