#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

make clean  # Not strictly necessary, since we are building in a fresh dir.
make -j$(nproc) all    # Build the fuzz targets.

# Copy the fuzzer executables, zip-ed corpora, option and dictionary files to $OUT
find . -name '*_fuzzer' -exec cp -v '{}' $OUT ';'
find . -name '*_fuzzer.dict' -exec cp -v '{}' $OUT ';'     # If you have dictionaries.
find . -name '*_fuzzer.options' -exec cp -v '{}' $OUT ';'  # If you have custom options.
