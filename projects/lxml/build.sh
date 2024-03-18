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
export STATIC_DEPS=true
export CFLAGS="$CFLAGS -fPIC"

if [ "$SANITIZER" = undefined ]; then
    # libiconv-1.17 (a dependency of libxml2) triggers several UBSAN errors similar to:
    # `utf32le.h:30:59: runtime error: left shift of 225 by 24 places cannot be represented in type 'int'`
    # Disabling the UBSAN shift check, while not ideal, appears to be the simplest way to avoid hindering the fuzzer
    # with false positives for now and libxml2 is already being fuzzed independently so there is little value in
    # checking it here as well.
    export CFLAGS="$CFLAGS -fno-sanitize=shift"
    export CXXFLAGS="$CXXFLAGS -fno-sanitize=shift"
fi
python3 -u setup.py build --static-deps --with-cython
python3 -m pip install .

DICT_DIR="$SRC/fuzzer_configuration/dictionaries"

find "$DICT_DIR" -name '*.dict' ! -name '__base.dict' -print0 | while IFS= read -r -d $'\0' fuzz_target_dict; do
    # Copy the .dict file to the output directory
    cp "$fuzz_target_dict" "$OUT"
    # Append __base.dict content to the copied file in $OUT
    cat "$DICT_DIR/__base.dict" >> "$OUT/$(basename "$fuzz_target_dict")"
done
for fuzzer in $(find "$SRC/fuzz_targets" -name 'fuzz_*.py'); do
  compile_python_fuzzer "$fuzzer"
done
