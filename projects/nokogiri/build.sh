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

export SANITIZER_LINK=""

if [ "$SANITIZER" = "undefined" ]
then
  export SANITIZER_LINK="$(find $(llvm-config --libdir) -name libclang_rt.ubsan_standalone_cxx-x86_64.a | head -1)"
fi
if [ "$SANITIZER" = "address" ]
then
  export SANITIZER_LINK="$(find $(llvm-config --libdir) -name libclang_rt.asan_cxx-x86_64.a | head -1)"
fi
if [ "$SANITIZER" = "memory" ]
then
  export SANITIZER_LINK="$(find $($LLVM_CONFIG --libdir) -name libclang_rt.msan_cxx-x86_64.a | head -1)"
fi

cd nokogiri/gumbo-parser/src && make clean && make && cd -
$CXX $CXXFLAGS -o parse_fuzzer parse_fuzzer.cc nokogiri/gumbo-parser/src/libgumbo.a $LIB_FUZZING_ENGINE $SANITIZER_LINK
mv parse_fuzzer $OUT/parse_fuzzer
mv gumbo.dict $OUT/parse_fuzzer.dict
mv nokogiri_corpus.zip $OUT/parse_fuzzer_seed_corpus.zip
