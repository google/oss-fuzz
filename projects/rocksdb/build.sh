# Copyright 2020 Google LLC
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

export CFLAGS="${CFLAGS} -DNDEBUG"
export CXXFLAGS="${CXXFLAGS} -DNDEBUG -std=c++17"

cd $SRC/LPM
export PKG_CONFIG_PATH=$PWD:$PWD/external.protobuf/lib/pkgconfig/
export PATH=$PWD/external.protobuf/bin:$PATH

cd $SRC/rocksdb
export FUZZ_ENV=ossfuzz
export CC=$CXX
export DISABLE_WARNING_AS_ERROR=1
make static_lib

cd fuzz
make db_fuzzer
make db_map_fuzzer

cp *_fuzzer $OUT/
