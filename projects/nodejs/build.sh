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
cd node

export LDFLAGS="-fsanitize=fuzzer-no-link -stdlib=libc++ -fsanitize=address"
export LD="clang++"

./configure
make -j4

# Build the fuzzer
cd src
mkdir fuzzers
cp /src/fuzz_url.cc ./fuzzers/

# Give the proper settings
CMDS="-DV8_DEPRECATION_WARNINGS -DV8_IMMINENT_DEPRECATION_WARNINGS \
 -D__STDC_FORMAT_MACROS -DOPENSSL_NO_PINSHARED -DOPENSSL_THREADS \
 -DNODE_ARCH=\"x64\" -DNODE_PLATFORM=\"linux\" -DNODE_WANT_INTERNALS=1 \
 -DHAVE_OPENSSL=1 -DHAVE_INSPECTOR=1 -D__POSIX__ -DNODE_HAVE_I18N_SUPPORT=1"

# Includes
INCLUDES="-I./ -I../deps/v8/include \
 -I../deps/uv/include -I../deps/openssl/openssl/include"

clang++ -o fuzzers/fuzz_url.o fuzzers/fuzz_url.cc $CXXFLAGS $CMDS $INCLUDES \
        -pthread -fno-omit-frame-pointer -fno-rtti -fno-exceptions -std=gnu++1y -MMD -c

cd /src/node/out
rm -rf ./library_files && mkdir library_files
find . -name "*.a" -exec cp {} ./library_files/ \;
rm ./library_files/libicutools.a

clang++ -o $OUT/fuzz_url $LIB_FUZZING_ENGINE $CXXFLAGS \
  -rdynamic -Wl,-z,noexecstack,-z,relro,-z,now \
  -pthread -Wl,--start-group \
  ./Release/obj.target/cctest/src/node_snapshot_stub.o \
  ./Release/obj.target/cctest/src/node_code_cache_stub.o \
  ../src/fuzzers/fuzz_url.o ./library_files/*.a \
  -latomic -lm -ldl -Wl,--end-group
