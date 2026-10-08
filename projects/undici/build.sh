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

npm install --ignore-scripts
npm install --no-save --ignore-scripts @jazzer.js/core

rm -rf "$OUT/undici" "$OUT/fuzz_headers" "$OUT/fuzz_request" "$OUT/fuzz_fetch_formdata"

JAZZER_SRC="$WORK/jazzerjs"
rm -rf "$JAZZER_SRC"
JAZZER_VERSION=$(node -p "require('./node_modules/@jazzer.js/core/package.json').version")
git clone --depth 1 --branch "v${JAZZER_VERSION}" \
	https://github.com/CodeIntelligenceTesting/jazzer.js "$JAZZER_SRC"

pushd "$JAZZER_SRC/packages/fuzzer"
npm install --ignore-scripts
CFLAGS_SAVE="$CFLAGS"
CXXFLAGS_SAVE="$CXXFLAGS"
unset CFLAGS
unset CXXFLAGS
CC=gcc CXX=g++ npx cmake-js build --out build
export CFLAGS="$CFLAGS_SAVE"
export CXXFLAGS="$CXXFLAGS_SAVE"
mkdir -p prebuilds
cp build/Release/jazzerjs.node prebuilds/fuzzer-linux-x64.node
popd

mkdir -p node_modules/@jazzer.js/fuzzer/prebuilds
cp "$JAZZER_SRC/packages/fuzzer/prebuilds/fuzzer-linux-x64.node" \
	node_modules/@jazzer.js/fuzzer/prebuilds/

compile_javascript_fuzzer undici fuzz_headers.js -i undici --sync
compile_javascript_fuzzer undici fuzz_request.js -i undici
compile_javascript_fuzzer undici fuzz_fetch_formdata.js -i undici
