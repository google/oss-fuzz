#!/bin/bash -eu
# Copyright 2021 Google Inc.
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

# afl++ workaround, as afl-clang-fast does not work yet.
test -n "$AFL_MAP_SIZE" && {
  export CC=clang
  export CXX=clang++
  AFL_FLAGS="-fsanitize-coverage=trace-pc-guard"
  # Future: enable 40% chance for cmplog lite
  # rm -f $WORK/afl_cmplog
  # test $(($RANDOM % 10)) -lt 4 && {
  #   AFL_FLAGS="$AFL_FLAGS,trace-cmp"
  #   touch $WORK/afl_cmplog
  # }
  export CFLAGS="$AFL_FLAGS $CFLAGS"
  export CXXFLAGS="$AFL_FLAGS $CXXFLAGS"
  rm -f $LIB_FUZZING_ENGINE
  ar ru $LIB_FUZZING_ENGINE $SRC/aflplusplus/afl-compiler-rt.o $SRC/aflplusplus/utils/aflpp_driver/aflpp_driver.o || exit 1
}

$SRC/libreoffice/bin/oss-fuzz-build.sh
