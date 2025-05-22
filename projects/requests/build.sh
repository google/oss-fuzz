#!/bin/bash -eu
# Copyright 2021 Google LLC
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
# Directory to look in for dictionaries, options files, and seed corpa:
SEED_DATA_DIR="$SRC/seed_data"

# Help Fuzz Introspector find the package entrypoint.
# See https://github.com/ossf/fuzz-introspector/issues/1010
export PYFUZZPACKAGE="$SRC/requests/src/requests"

# Build and install project (using current CFLAGS, CXXFLAGS).
python3 -m pip install .

find $SEED_DATA_DIR \( -name '*_seed_corpus.zip' -o -name '*.options' -o -name '*.dict' \) \
  ! \( -name '__base.*' \) -exec printf 'Copying: %s\n' {} \; \
  -exec chmod a-x {} \; \
  -exec cp {} "$OUT" \;

find "$SRC" -maxdepth 1 -name 'fuzz_*.py' -print0 | while IFS= read -r -d $'\0' fuzz_harness; do
  compile_python_fuzzer "$fuzz_harness"

  common_base_dictionary_filename="$SEED_DATA_DIR/__base.dict"
  if [[ -r "$common_base_dictionary_filename" ]]; then
    # Strip the `.py` extension from the filename and replace it with `.dict`.
    fuzz_harness_dictionary_filename="$(basename "$fuzz_harness" .py).dict"

    printf 'Appending %s to %s\n' "$common_base_dictionary_filename" "$OUT/$fuzz_harness_dictionary_filename"
    cat "$common_base_dictionary_filename" >> "$OUT/$fuzz_harness_dictionary_filename"
  fi
done
