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

# The full dependency tree (Electron, Bun workspace) is not needed: install
# only the bundler and the XML parser at their pinned ranges.
XMLDOM=$(node -p "require('./package.json').dependencies['@xmldom/xmldom']")
ESBUILD=$(node -p "require('./package.json').devDependencies.esbuild")
mv package.json package.json.orig
npm install --no-save --no-audit --no-fund "@xmldom/xmldom@$XMLDOM" "esbuild@$ESBUILD"
mv package.json.orig package.json
sh fuzz/build.sh

# The bundles are self-contained: ship only them plus Jazzer.js, not the repo.
# Jazzer.js 2.1.0: the 4.x prebuilds need a newer glibc than base-runner has.
FUZZ_DIR=$SRC/exelearning-fuzz
mkdir -p $FUZZ_DIR
cp fuzz/dist/*.js $FUZZ_DIR/
(cd $FUZZ_DIR && npm init -y >/dev/null && npm install --no-audit --no-fund @jazzer.js/core@2.1.0)

# Seed corpus: content.xml from the legacy .elp fixtures.
CORPUS=$WORK/elp_corpus
mkdir -p $CORPUS
for f in test/fixtures/*.elp; do
  unzip -p "$f" content.xml > "$CORPUS/$(basename "$f" .elp).xml" 2>/dev/null || true
done
zip -jq $OUT/legacy_xml_parser.fuzz_seed_corpus.zip $CORPUS/*.xml

compile_javascript_fuzzer exelearning-fuzz legacy_xml_parser.fuzz.js --sync --timeout=10
compile_javascript_fuzzer exelearning-fuzz safe_join.fuzz.js --sync
