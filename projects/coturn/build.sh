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

mkdir my_build

pushd my_build/
cmake -DFUZZER=ON -DLIB_FUZZING_ENGINE="$LIB_FUZZING_ENGINE" \
    -DCMAKE_EXE_LINKER_FLAGS="-Wl,-rpath,'\$ORIGIN/lib'" -DWITH_MYSQL=OFF -Wno-dev ../.
make -j$(nproc)
popd

pushd my_build/fuzzing/
cp FuzzStun $OUT/FuzzStun
cp FuzzStunClient $OUT/FuzzStunClient
popd

pushd fuzzing/input/
cp FuzzStun_seed_corpus.zip $OUT/FuzzStun_seed_corpus.zip
cp FuzzStunClient_seed_corpus.zip $OUT/FuzzStunClient_seed_corpus.zip
popd

pushd /lib/x86_64-linux-gnu/
mkdir $OUT/lib/
cp libevent* $OUT/lib/.
popd
