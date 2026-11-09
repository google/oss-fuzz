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

# Install dependencies.
npm install
npm install uglify-js fs -g
npm install --save-dev @jazzer.js/core

# Combine needed js and the fuzzers
uglifyjs $SRC/parseTools-fuzzer-base.js $SRC/emscripten/src/utility.js \
    $SRC/emscripten/src/parseTools.js -o $SRC/parseTools-fuzzer.js -c -m
uglifyjs $SRC/jsifier-fuzzer-base.js $SRC/emscripten/src/modules.js \
    $SRC/emscripten/src/jsifier.js -o $SRC/jsifier-fuzzer.js -c -m

# Build Fuzzers.
compile_javascript_fuzzer emscripten ./src/parseTools-fuzzer.js --sync
compile_javascript_fuzzer emscripten ./src/jsifier-fuzzer.js --sync
cp $SRC/*-fuzzer.js $OUT/emscripten/src/
