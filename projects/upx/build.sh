#!/bin/bash -eu
# Copyright 2023 Google LLC
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

# Temporary fix for clang bug of upx
sed -i 's/ \&\& __clang_major__ < 15//m' /src/upx/src/util/util.cpp
git apply   --ignore-space-change --ignore-whitespace  $SRC/upx/fuzzers/build.patch

# build project
# e.g.
mkdir -p build/debug
cd build/debug
cmake ../..

for fuzzer in $(find $SRC -name '*_fuzzer.cpp'); do
    fuzz_basename=$(basename -s .cpp $fuzzer)
    cmake --build . --target $fuzz_basename -v
done

cp ./*_fuzzer $OUT/

mkdir -p $SRC/corpus/

cp $SRC/testsuite3/files/corpus/* $SRC/corpus/

for architecture in $(ls $SRC/testsuite/files/packed/); do
    for file in $(ls $SRC/testsuite/files/packed/$architecture); do
        cp $SRC/testsuite/files/packed/$architecture/$file $SRC/corpus/$architecture-$file
    done
done

for architecture in $(ls $SRC/testsuite2/files/all/); do
    for file in $(ls $SRC/testsuite2/files/all/$architecture); do
        cp $SRC/testsuite2/files/all/$architecture/$file $SRC/corpus/$architecture-$file
    done
done

# build corpora
# e.g.
for fuzzer in $(find $SRC -name '*_fuzzer.cpp'); do
    fuzz_basename=$(basename -s .cpp $fuzzer)
    zip -q $OUT/${fuzz_basename}_seed_corpus.zip $SRC/corpus/*
done
