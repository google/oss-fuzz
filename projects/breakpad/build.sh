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

cd breakpad
mkdir $SRC/breakpad/src/third_party/lss 
cp $SRC/linux-syscall-support/linux_syscall_support.h \
  $SRC/breakpad/src/third_party/lss/
./configure
make -j$(nproc)
$CXX $CXXFLAGS -I$SRC/breakpad/src -c $SRC/breakpad_fuzzer.cc \
  -o breakpad_fuzzer.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE breakpad_fuzzer.o \
  -o $OUT/breakpad_fuzzer ./src/libbreakpad.a
