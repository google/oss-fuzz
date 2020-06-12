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
cd $SRC/node

# Build node
export LDFLAGS="$CXXFLAGS"
export LD="$CXX"
./configure --without-intl --without-node-code-cache --without-dtrace --without-snapshot --without-ssl
make -j$(nproc)

# Gather static libraries
cd $SRC/node/out
rm -rf ./library_files && mkdir library_files
find . -name "*.a" -exec cp {} ./library_files/ \;

# Build the fuzzers
CMDS="-D__STDC_FORMAT_MACROS -D__POSIX__ -DNODE_HAVE_I18N_SUPPORT=1 \
 -DNODE_ARCH=\"x64\" -DNODE_PLATFORM=\"linux\" -DNODE_WANT_INTERNALS=1"
INCLUDES="-I../src -I../deps/v8/include -I../deps/uv/include"

# Compilation
$CXX -o fuzz_url.o $SRC/fuzz_url.cc $CXXFLAGS $CMDS $INCLUDES \
        -pthread -fno-omit-frame-pointer -fno-rtti -fno-exceptions -std=gnu++1y -MMD -c

# Linking
$CXX -o $OUT/fuzz_url $LIB_FUZZING_ENGINE $CXXFLAGS \
  -rdynamic -Wl,-z,noexecstack,-z,relro,-z,now \
  -pthread -Wl,--start-group \
  ./Release/obj.target/cctest/src/node_snapshot_stub.o \
  ./Release/obj.target/cctest/src/node_code_cache_stub.o \
  fuzz_url.o ./library_files/*.a \
  -latomic -lm -ldl -Wl,--end-group
