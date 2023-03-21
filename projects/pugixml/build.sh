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
cd pugixml

$CXX $CXXFLAGS -c src/pugixml.cpp -o src/pugixml.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE tests/fuzz_parse.cpp src/pugixml.o -o ${OUT}/fuzz_parse
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE tests/fuzz_xpath.cpp src/pugixml.o -o ${OUT}/fuzz_xpath

zip -r ${OUT}/fuzz_parse_seed_corpus.zip tests/data_fuzz_parse
zip -r ${OUT}/fuzz_xpath_seed_corpus.zip tests/data_fuzz_xpath tests/data_fuzz_parse

cp tests/fuzz_parse.dict ${OUT}/fuzz_parse.dict
cp tests/fuzz_xpath.dict ${OUT}/fuzz_xpath.dict
cat ${OUT}/fuzz_parse.dict >> ${OUT}/fuzz_xpath.dict
