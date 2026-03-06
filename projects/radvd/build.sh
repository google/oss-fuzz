#!/bin/bash -eux
# Copyright 2026 Google LLC
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

./autogen.sh
./configure
make -j$(nproc)

# Compile harnesses
$CC $CFLAGS -I. -c $SRC/fuzz_config.c -o fuzz_config.o
$CC $CFLAGS -I. -c $SRC/fuzz_process.c -o fuzz_process.o

# Objects to link against
# We exclude radvd.o (main), radvdump.o (main), log.o (mocked)
OBJS="util.o interface.o device-common.o device-linux.o privsep-linux.o recv.o socket.o send.o timer.o"

# fuzz_config
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_config.o libradvd-parser.a $OBJS -l:libbsd.a -o $OUT/fuzz_config

# fuzz_process
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_process.o process.o $OBJS /usr/lib/x86_64-linux-gnu/libbsd.a -o $OUT/fuzz_process
