
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

cd $SRC/kamailio

# export CFLAGS="${CFLAGS}"
export LDFLAGS="${CFLAGS}"

mkdir -p build
cd build
cmake -DVERBOSE=ON \
      -DPKG_MALLOC=OFF \
      -DMODULE_GROUP_NAME="" \
      -G "Unix Makefiles" ..
make -j$(nproc) kamailio-oss-fuzz || true  

cd ../

$CC $CFLAGS -c ./misc/fuzz/fuzz_uri.c -o fuzz_uri.o \
    -DFAST_LOCK -D__CPU_i386 \
    -I./src/ -I./src/core/parser

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_uri.o -o $OUT/fuzz_uri \
    ./build/src/libkamailio-oss-fuzz.a -ldl -lresolv -lm

$CC $CFLAGS ./misc/fuzz/fuzz_parse_msg.c -c -o fuzz_parse_msg.o \
    -DFAST_LOCK -D__CPU_i386 \
    -I./src/ -I./src/core/parser

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_parse_msg.o -o $OUT/fuzz_parse_msg \
    ./build/src/libkamailio-oss-fuzz.a -ldl -lresolv -lm