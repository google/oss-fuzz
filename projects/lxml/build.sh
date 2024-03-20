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

# Flags to link sanitizers at runtime.
# Anything not forwarded is required by lxml.
export CFLAGS="$CFLAGS -fPIC"
export CXXFLAGS="$CXXFLAGS -fPIC"
## Use LD values if already set, (Fuzz Introspector may set them) otherwise use the OSS-Fuzz suggested linker and flags.
: "${LD:=${CXX}}"
: "${LDFLAGS:=${CXXFLAGS}}"

if [[ "$SANITIZER" = 'undefined' ]]; then
  # libiconv-1.17 (a dependency of libxml2) triggers several UBSAN errors similar to:
  # `utf32le.h:30:59: runtime error: left shift of 225 by 24 places cannot be represented in type 'int'`
  # Disabling the UBSAN shift check, while not ideal, appears to be the simplest way to avoid hindering the fuzzer
  # with false positives for now and libxml2 is already being fuzzed independently so there is little value in
  # checking it here as well.
  export CFLAGS+=" -fno-sanitize=shift"
  export CXXFLAGS+=" -fno-sanitize=shift"
fi
# lxml build Settings
if [[ $SANITIZER = *coverage* ]] || [[ $SANITIZER = 'introspector' ]]; then
  export COVERAGE=1
  export OPTION_WITH_COVERAGE=1
fi
export STATICBUILD=1

make require-cython
make clean
make SETUPFLAGS='--with-clines --with-unicode-strings' build PYTHON_WITH_CYTHON='--with-cython' -j"$(nproc)"
python3 -m pip install .

SEED_DATA_DIR="$SRC/seed_data"

find $SEED_DATA_DIR \( -name '*_seed_corpus.zip' -o -name '*.options' -o -name '*.dict' \) \
  ! \( -name '__base.dict' \) -exec printf 'Copying: %s\n' {} \; \
  -exec chmod a-x {} \; \
  -exec cp {} "$OUT" \;

find "$SRC" -maxdepth 1 -name 'fuzz_*.py' -print0 | while IFS= read -r -d $'\0' fuzz_harness; do
  compile_python_fuzzer "$fuzz_harness" \
    --collect-all="lxml"

  if [[ -r "$SEED_DATA_DIR/__base.dict" ]]; then
    fuzz_harness_basename=$(basename "$fuzz_harness")
    # Copy the shared dictionary file content to a fuzz target specific .dict in $OUT.
    cat "$SEED_DATA_DIR/__base.dict" >>"$OUT/$fuzz_harness_basename.dict"
  fi
done
