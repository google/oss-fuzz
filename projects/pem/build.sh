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

python3 -m pip install .

make_dictionary_for_fuzz_harness() {
  local fuzz_harness="$1"
  local base_dictionary="$SRC/__base.dict"
  local output_dict="$OUT/${fuzz_harness##*/}"
  output_dict="${output_dict%.py}.dict"

  [[ -r "$base_dictionary" ]] && {
    [[ -s "$output_dict" ]] && echo >>"$output_dict"
    cat "$base_dictionary" >>"$output_dict"
  }
}

for fuzzer in $(find $SRC -name 'fuzz_*.py'); do
  compile_python_fuzzer $fuzzer
  make_dictionary_for_fuzz_harness "$fuzzer"
done

zip -rj $OUT/fuzz_pem_seed_corpus.zip $SRC/data.pem
