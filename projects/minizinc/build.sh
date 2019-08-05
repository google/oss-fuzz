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

build_dir=$WORK/build

mkdir -p $build_dir
pushd $build_dir
cmake $SRC/minizinc -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DCMAKE_INSTALL_PREFIX=$WORK/install
cmake --build . --target install -- -j$(nproc)
popd

$CXX $CXXFLAGS -std=c++11 -I$WORK/install/include $SRC/minizinc/minizinc_fuzzer.cpp -o $OUT/minizinc_fuzzer $LIB_FUZZING_ENGINE $WORK/install/lib/libmzn.a

rm -rf $OUT/share
mv $WORK/install/share $OUT
mv $SRC/minizinc_fuzzer_seed_corpus.zip $OUT/minizinc_fuzzer_seed_corpus.zip
mv $SRC/minizinc_fuzzer.dict $OUT/minizinc_fuzzer.dict
mv $SRC/minizinc_fuzzer.options $OUT/minizinc_fuzzer.options