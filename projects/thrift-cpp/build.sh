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

export ASAN_OPTIONS=detect_leaks=0

# Build and install the compiler (disable other languages to save time)
./bootstrap.sh
./configure --enable-static --disable-shared --with-cpp=yes --with-c_glib=no --with-python=no --with-py3=no --with-go=no --with-rs=no --with-java=no --with-nodejs=no --with-dotnet=no --with-kotlin=no
make -j$(nproc)
make install

# Build C++ library and fuzzers
pushd lib/cpp/test/fuzz
make check
for i in $(find . -maxdepth 1 -type f -executable -printf "%f\n"); do
    cp $i $OUT/$i
done
popd 