#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

NAME=parse_fuzzer

zip -j /out/${NAME}_seed_corpus.zip $(find /src/JSON-Schema-Test-Suite/tests/draft4 -name '*.json')

cd /src/rapidjson
$CXX $CXXFLAGS -std=c++11 -Iinclude ${NAME}.cc -o /out/${NAME} -lfuzzer $FUZZER_LDFLAGS
