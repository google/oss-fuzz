#!/bin/bash -eu
# Copyright 2025 Google LLC
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

# ===== BUILD Sqlite =====
SQLITE_VER=sqlite-autoconf-3480000

wget https://www.sqlite.org/2025/${SQLITE_VER}.tar.gz
tar xzf ${SQLITE_VER}.tar.gz
cd ${SQLITE_VER}
./configure --enable-static --disable-shared
make -j"$(nproc)"
make install
cd ..

# ===== BUILD zeroMQ =====
git clone https://github.com/zeromq/libzmq.git
cd libzmq
mkdir build && cd build
cmake .. -DBUILD_SHARED=OFF -DBUILD_STATIC=ON -DZMQ_BUILD_TESTS=OFF
make -j"$(nproc)"
make install
cd ../..

# ===== Build BehaviorTree.CPP =====
mkdir build && cd build

CMAKE_FLAGS=(
  "-DCMAKE_BUILD_TYPE=Release"
  "-DENABLE_FUZZING=ON"
  "-DFORCE_STATIC_LINKING=ON"
)

cmake .. "${CMAKE_FLAGS[@]}"
make -j"$(nproc)"

for fuzzer in bt_fuzzer script_fuzzer bb_fuzzer; do
  cp $fuzzer "$OUT/"

  if [ -d ../fuzzing/corpus/${fuzzer} ]; then
    zip -j "$OUT/${fuzzer}_seed_corpus.zip" ../fuzzing/corpus/${fuzzer}/*
  fi
done
