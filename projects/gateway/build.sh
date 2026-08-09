#!/bin/bash -eu
# Copyright 2025 Google LLC
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

$SRC/gateway/test/fuzz/oss_fuzz_build.sh

# Copy default.options to all fuzzers in $OUT if they don't have specific options files
for fuzzer in "$OUT"/*; do
  # Skip non-files and files with extensions
  [[ ! -f "$fuzzer" ]] || [[ "$fuzzer" == *.* ]] && continue
  
  fuzzer_name=$(basename "$fuzzer")
  options_file="$OUT/${fuzzer_name}.options"
  
  if [[ ! -f "$options_file" ]] && [[ -f "$SRC/default.options" ]]; then
    cp "$SRC/default.options" "$options_file"
  fi
done
