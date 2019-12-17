#!/bin/bash -eu
# Copyright 2017 Google Inc.
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

cd llvm-project

if [[ $SANITIZER = *undefined* ]]; then
  CXXFLAGS="$CXXFLAGS -fsanitize=unsigned-integer-overflow -fsanitize-trap=unsigned-integer-overflow"
fi

for f in $(grep -v "#" libcxx/fuzzing/RoutineNames.txt); do
  cat > ${f}_fuzzer.cc <<EOF
#include "fuzzing/fuzzing.h"
#include <cassert>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int result = fuzzing::$f(data, size);
  assert(result == 0); return 0;
}
EOF
  $CXX $CXXFLAGS -std=c++11 ${f}_fuzzer.cc ./libcxx/fuzzing/fuzzing.cpp \
      -nostdinc++ -cxx-isystem ./libcxx/include -iquote ./libcxx \
      -o $OUT/$f $LIB_FUZZING_ENGINE
done
