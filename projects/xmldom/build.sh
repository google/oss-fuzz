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

# install dependencies
npm ci
# no longer part of xmldom devDependencies since it can no longer be installed reliably
npm i -D @jazzer.js/core

# prepare corpus
XMLTEST_CORPUS=$OUT/xmldom/xmltest
mkdir -p $XMLTEST_CORPUS
# extract all *.xml files without a folder structure,
# renaming duplicate filenames with ~, ~1, ~2, ...
# into the target directory
unzip -Bj node_modules/xmltest/xmltest.zip '*.xml' -d $XMLTEST_CORPUS

# build fuzzers
compile_javascript_fuzzer xmldom fuzz/dom-parser.xml.target.js --sync --timeout=10 $XMLTEST_CORPUS
compile_javascript_fuzzer xmldom fuzz/dom-parser.html.target.js --sync --timeout=10 $XMLTEST_CORPUS
