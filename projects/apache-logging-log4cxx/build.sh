#!/bin/bash -eu
# Copyright 2021 Google LLC
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

git clone --quiet --depth 1 --branch master --single-branch https://github.com/apache/logging-log4cxx
./logging-log4cxx/src/fuzzers/bash/oss-fuzz-build.sh "$OUT"

# Add seed corpus
zip $OUT/DOMConfiguratorFuzzer_seed_corpus.zip $SRC/logging-log4cxx/src/test/resources/input/xml/*.xml
