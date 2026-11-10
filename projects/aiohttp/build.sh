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
#
# aiofastnet (an optional aiohttp speed-up) is deliberately left out of the
# bundles. The cython parts fail through PyInstaller.
for fuzzer in $(find $SRC/aiohttp/fuzzers -name '*.py'); do
  compile_python_fuzzer $fuzzer --paths $SRC/aiohttp --exclude-module aiofastnet
done

# aiohttp/fuzzers/no_extensions.txt defines which fuzzers should be run
# a second time with extensions disabled.
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
    pure_python_name="${fuzzer_name}_pure_python"
    # For pure Python, copy the fuzzer and it's dependencies.
    cp "$OUT/$fuzzer_name.pkg" "$OUT/$pure_python_name.pkg"
    if [[ -f "$OUT/$fuzzer_name.pkg.deps.zip" ]]; then
      cp "$OUT/$fuzzer_name.pkg.deps.zip" "$OUT/$pure_python_name.pkg.deps.zip"
    fi
    sed -e "s|/$fuzzer_name\.pkg|/$pure_python_name.pkg|g" \
        -e '2i export AIOHTTP_NO_EXTENSIONS=1' \
        "$OUT/$fuzzer_name" > "$OUT/$pure_python_name"
    chmod +x "$OUT/$pure_python_name"
  done < "$no_extensions_file"
fi
