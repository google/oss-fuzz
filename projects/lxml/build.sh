#!/bin/bash -eu
# Copyright 2022 Google LLC
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

export LIBXML2_VERSION=2.12.6
export LIBXSLT_VERSION=1.1.39
export STATICBUILD=true
export CFLAGS="$CFLAGS -fPIC -DCYTHON_CLINE_IN_TRACEBACK=1"

if [[ $SANITIZER = *coverage* ]]; then
  export COVERAGE=true
  export OPTION_WITH_COVERAG=true
  export OPTION_WITH_CLINE=true
fi

if [[ "$SANITIZER" = 'undefined' ]]; then
  # libiconv-1.17 (a dependency of libxml2) triggers several UBSAN errors similar to:
  # `utf32le.h:30:59: runtime error: left shift of 225 by 24 places cannot be represented in type 'int'`
  # Disabling the UBSAN shift check, while not ideal, appears to be the simplest way to avoid hindering the fuzzer
  # with false positives for now and libxml2 is already being fuzzed independently so there is little value in
  # checking it here as well.
  export CFLAGS="$CFLAGS -fno-sanitize=shift"
  export CXXFLAGS="$CXXFLAGS -fno-sanitize=shift"
fi
python3 -u setup.py build --with-cython
python3 -m pip install .

SEED_DATA_DIR="$SRC/seed_data"

find "$SEED_DATA_DIR" \( -name '*_seed_corpus.zip' -o -name '*.dict' \)  ! -name '__base.dict' -exec printf 'Copying: %s\n' {} \; -exec cp {} "$OUT" \;

find "$SRC" -name 'fuzz_*.py' -print0 | while IFS= read -r -d $'\0' fuzz_harness; do
   compile_python_fuzzer "$fuzz_harness" --add-data="$SRC/lxml/build/lib.linux-x86_64-cpython-38/lxml:."

  if [[ -r "$SEED_DATA_DIR/dicts/__base.dict" ]]; then
    fuzz_harness_basename=$(basename "$fuzz_harness")
    # Append __base.dict content to the copied file in $OUT
    cat "$SEED_DATA_DIR/dicts/__base.dict" >> "$OUT/$fuzz_harness_basename.dict"
  fi
done
