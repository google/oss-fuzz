#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

#!/bin/bash -eu

cd $SRC/iroha
./clean.sh
mkdir build
cd build
 
cmake -DCMAKE_TOOLCHAIN_FILE=/opt/dependencies/scripts/buildsystems/vcpkg.cmake -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" -DFUZZING=ON ..
make -j$(nproc) find_fuzz
make -j$(nproc) torii_fuzz
make -j$(nproc) status_fuzz
make -j$(nproc) send_batches_fuzz
make -j$(nproc) request_proposal_fuzz
make -j$(nproc) retrieve_block_fuzz
make -j$(nproc) retrieve_blocks_fuzz
make -j$(nproc) consensus_fuzz
make -j$(nproc) mst_fuzz
  
cp test_bin/* $OUT/