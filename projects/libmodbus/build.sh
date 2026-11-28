#!/bin/bash -eu
# Copyright 2022 Google LLC
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

cd fuzz
make all

cp FuzzClient $OUT/FuzzClient
cp FuzzServer $OUT/FuzzServer

pushd $SRC/oss-fuzz-bloat/libmodbus/
cp FuzzClient_seed_corpus.zip $OUT/FuzzClient_seed_corpus.zip
cp FuzzServer_seed_corpus.zip $OUT/FuzzServer_seed_corpus.zip
popd

# FuzzLM: in-process harness (socketpair, no network, no threads) that drives
# modbus_reply, modbus_proxy, the client functions and the TCP/RTU framing.
# `make all` above already built ../src/.libs/libmodbus.a with the fuzzing flags.
$CC $CFLAGS -I../src -c FuzzLM.c -o FuzzLM.o
$CXX $CXXFLAGS FuzzLM.o ../src/.libs/libmodbus.a $LIB_FUZZING_ENGINE -o $OUT/FuzzLM
python3 gen_seeds.py FuzzLM_seeds
python3 -c "import shutil,sys; shutil.make_archive(sys.argv[1], 'zip', sys.argv[2])" \
    $OUT/FuzzLM_seed_corpus FuzzLM_seeds
cp FuzzLM.dict $OUT/FuzzLM.dict
