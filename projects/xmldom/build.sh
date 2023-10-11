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

# build project
npm ci
unzip node_modules/xmltest/xmltest.zip

# build fuzzers
compile_javascript_fuzzer xmldom fuzz/dom-parser.xml.target.js --sync --timeout=10 xmltest
compile_javascript_fuzzer xmldom fuzz/dom-parser.html.target.js --sync --timeout=10 xmltest
