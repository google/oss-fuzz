#!/bin/bash -eu
# Copyright 2020 Google Inc.
# Copyright 2020 Luca Boccassi <bluca@debian.org>
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

cd $SRC/rocksdb
make static_lib -j$(nproc)

# Copy options out
cp $SRC/*options $OUT/

$CXX $CXXFLAGS -c ./db/fuzz_db.cc -o fuzz_db.o -I./include
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_db.o -o $OUT/fuzz_db ./librocksdb.a -lpthread -lrt -ldl  -ldl -lpthread
