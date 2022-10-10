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
./configure --debug --no-regex --no-pcre2
make all

pushd fuzzer/
make
cp Fuzz_http $OUT/Fuzz_http
cp Fuzz_json $OUT/Fuzz_json
popd

pushd $SRC/oss-fuzz-bloat/nginx-unit/
cp Fuzz_http_seed_corpus.zip $OUT/Fuzz_http_seed_corpus.zip
cp Fuzz_json_seed_corpus.zip $OUT/Fuzz_json_seed_corpus.zip
popd
