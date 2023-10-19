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
###############################################################################

cd nokogiri/gumbo-parser/src && make clean && make && cd -
$CXX $CXXFLAGS -o parse_fuzzer parse_fuzzer.cc nokogiri/gumbo-parser/src/libgumbo.a $LIB_FUZZING_ENGINE
mv parse_fuzzer $OUT/parse_fuzzer
mv gumbo.dict $OUT/parse_fuzzer.dict
mv nokogiri_corpus.zip $OUT/parse_fuzzer_seed_corpus.zip
