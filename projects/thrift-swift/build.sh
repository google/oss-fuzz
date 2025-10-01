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

. precompile_swift

export ASAN_OPTIONS=detect_leaks=0

# Disable other languages to save on compile time
./bootstrap.sh
./configure --enable-static --disable-shared --with-cpp=no --with-c_glib=no --with-python=no --with-py3=no --with-go=no --with-rs=no --with-java=no --with-nodejs=no --with-dotnet=no --with-kotlin=no --with-swift=yes
make -j$(nproc)

pushd lib/swift
make fuzz

(
cd FuzzTesting/.build/release/
find . -maxdepth 1 -type f -name "Fuzz*" -executable | while read i; do 
    cp $i $OUT/"$i"-release; 
    cp $SRC/default.options $OUT/"$i"-release.options; 
done
)
popd

