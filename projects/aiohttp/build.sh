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
# Build the llhttp parser
git submodule update --init --recursive
pushd "$SRC/aiohttp/vendor/llhttp/"
npm ci
make
popd # "$SRC/aiohttp/vendor/llhttp/"

# Build & install aiohttp
make cythonize
make install-dev

# Build fuzzers in $OUT. The fuzzers live in aiohttp/fuzzers/ (not at the repo root),
# so PyInstaller needs an explicit path to find aiohttp,
# which is only installed as an editable package.
for fuzzer in $(find $SRC/aiohttp/fuzzers -name '*.py'); do
  compile_python_fuzzer $fuzzer --paths $SRC/aiohttp
done

# Some fuzzers are also run against aiohttp's pure-Python implementation
# (AIOHTTP_NO_EXTENSIONS=1), in addition to the default C-compiled one.
# aiohttp controls which ones by listing them in aiohttp/fuzzers/no_extensions.txt
# (one fuzzer target per line, matching the $OUT binary name, i.e. the fuzzer
# basename without the .py suffix; blank lines and # comments are allowed).
# Each listed fuzzer reuses the already-built binary: we create a
# <name>_pure_python wrapper that exports the env var. aiohttp reads
# AIOHTTP_NO_EXTENSIONS at import time in aiohttp/helpers.py, so the fuzzer
# source is identical in both cases. compile_python_fuzzer generates an sh
# wrapper whose first line is the shebang, so we insert the export right
# after it.
no_extensions_file="$SRC/aiohttp/fuzzers/no_extensions.txt"
if [[ -f "$no_extensions_file" ]]; then
  while read -r fuzzer_name; do
    # Tolerate CRLF line endings.
    fuzzer_name=${fuzzer_name%$'\r'}
    # Skip blank lines and comments.
    if [[ -z "$fuzzer_name" || "$fuzzer_name" == \#* ]]; then
      continue
    fi
    # Accept either the fuzzer basename or its source file name.
    fuzzer_name=${fuzzer_name%.py}
    if [[ ! -f "$OUT/$fuzzer_name" ]]; then
      echo "ERROR: '$fuzzer_name' is listed in $no_extensions_file but no fuzzer with that name was built." >&2
      exit 1
    fi
    cp "$OUT/$fuzzer_name" "$OUT/${fuzzer_name}_pure_python"
    sed -i '2i export AIOHTTP_NO_EXTENSIONS=1' "$OUT/${fuzzer_name}_pure_python"
  done < "$no_extensions_file"
fi
