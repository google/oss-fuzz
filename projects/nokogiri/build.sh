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

export SANITIZER_OPTS=""
export SANITIZER_LINK=""

if [ "$FUZZING_ENGINE" = "centipede" ]
then
  export CXXFLAGS="-fsanitize-coverage=trace-pc-guard,pc-table,trace-cmp -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fno-builtin -gline-tables-only"
  export CFLAGS="-fsanitize-coverage=trace-pc-guard,pc-table,trace-cmp -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fno-builtin -gline-tables-only"
  export ENGINE_LINK="$LIB_FUZZING_ENGINE -lc++"
fi
if [ "$FUZZING_ENGINE" = "libfuzzer" ]
then
  export CXXFLAGS="-fsanitize=fuzzer-no-link"
  export CFLAGS="-fsanitize=fuzzer-no-link"
  export ENGINE_LINK="$(find $(llvm-config --libdir) -name libclang_rt.fuzzer-x86_64.a | head -1)"
fi
if [ "$FUZZING_ENGINE" = "honggfuzz" ]
then
  export CXXFLAGS="-fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp"
  export CFLAGS="-fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp"
  export ENGINE_LINK="$(find . -name honggfuzz.a)"
fi
if [ "$FUZZING_ENGINE" = "afl" ]
then
  export CXXFLAGS="-fsanitize=fuzzer-no-link -fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp"
  export CFLAGS="-fsanitize=fuzzer-no-link -fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp"
  export ENGINE_LINK="$(find . -name libAFLDriver.a | head -1) $(find . -name afl-compiler-rt-64.o | head -1)"
fi

if [ "$SANITIZER" = "undefined" ]
then
  export SANITIZER_OPTS="-fsanitize=undefined"
  export SANITIZER_LINK="$(find $(llvm-config --libdir) -name libclang_rt.ubsan_standalone_cxx-x86_64.a | head -1)"
fi
if [ "$SANITIZER" = "address" ]
then
  export SANITIZER_OPTS="-fsanitize=address"
  export SANITIZER_LINK="$(find $(llvm-config --libdir) -name libclang_rt.asan_cxx-x86_64.a | head -1)"
fi
if [ "$SANITIZER" = "coverage" ]
then
  export SANITIZER_OPTS="-g -fprofile-instr-generate -fcoverage-mapping"
  export SANITIZER_LINK=""
fi


export CXXFLAGS="-O0 $CXXFLAGS $SANITIZER_OPTS"
export CFLAGS="-O0 $CFLAGS $SANITIZER_OPTS"
cd nokogiri/gumbo-parser/src && make clean && make && cd -
$CXX $CXXFLAGS -o parse_fuzzer parse_fuzzer.cc nokogiri/gumbo-parser/src/libgumbo.a $ENGINE_LINK $SANITIZER_LINK
mv parse_fuzzer $OUT/parse_fuzzer
mv gumbo.dict $OUT/parse_fuzzer.dict
mv nokogiri_corpus.zip $OUT/parse_fuzzer_seed_corpus.zip