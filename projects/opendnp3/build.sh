#!/bin/bash -eu
# Copyright 2018 Google Inc.
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


# The cmake version that is available on Ubuntu 16.04 is 3.5.1. OpenDNP3
# needs CMake 3.8 or higher, because of the C# bindings. Therefore, we
# manually install a modern CMake until the OSS Fuzz environment updates
# to a more recent Ubuntu.
wget https://cmake.org/files/v3.12/cmake-3.12.0-Linux-x86_64.tar.gz
tar -xzf cmake-3.12.0-Linux-x86_64.tar.gz
cp -r cmake-3.12.0-Linux-x86_64/bin /usr/local
cp -r cmake-3.12.0-Linux-x86_64/share /usr/local
rm -rf cmake-3.12.0-Linux-x86_64 cmake-3.12.0-Linux-x86_64.tar.gz

# build project
cmake -DDNP3_FUZZING=ON -DSTATICLIBS=ON .
make -j$(nproc) all

cd cpp/tests/fuzz

TARGETS="fuzzdecoder \
  fuzzoutstation \
  fuzzmaster"

for target in $TARGETS; do
  # build corpus
  zip -r ${target}_seed_corpus.zip corpus/*.dnp
  cp ${target}_seed_corpus.zip $OUT/

  # export other associated stuff
  cp fuzzdnp3.options $OUT/${target}.options

  # build fuzz target
  $CXX $CXXFLAGS -I. -I ../../libs/include/ -I ../../tests/libs/src/ -I ../../libs/src/ -c ${target}.cpp -o ${target}.o
  $CXX $CXXFLAGS -std=c++14 ${target}.o -o $OUT/${target} ../../../libdnp3mocks.a ../../../libtestlib.a ../../../libasiodnp3.a ../../../libdnp3decode.a ../../../libasiopal.a ../../../libopendnp3.a ../../../libopenpal.a $LIB_FUZZING_ENGINE
done
