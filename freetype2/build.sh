#!/bin/bash -eux
#
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
. /env

cd /workspace/

./autogen.sh
./configure
make

$CXX $CXXFLAGS $LDFLAGS -std=c++11 ./src/tools/ftfuzzer/ftfuzzer.cc \
  ./objs/*.o /work/libfuzzer/*.o \
   -nodefaultlibs -Wl,-Bdynamic -lpthread -lrt -lm -ldl -lgcc_s -lgcc -lc \
   -Wl,-Bstatic -lc++ -lc++abi \
   -larchive -I./include -I. ./objs/.libs/libfreetype.a  \
   -o /out/freetype2_fuzzer
