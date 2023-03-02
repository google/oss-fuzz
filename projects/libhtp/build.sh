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

# build project
(
cd libhtp-rs
export CARGO_BUILD_TARGET="x86_64-unknown-linux-gnu"
cargo fuzz build -O
cargo fuzz list | while read i; do
    # debug for coverage build
    cp fuzz/target/x86_64-unknown-linux-gnu/release/$i $OUT/ || cp fuzz/target/x86_64-unknown-linux-gnu/debug/$i $OUT/
done
if [ "$SANITIZER" = "address" ]
then
    export RUSTFLAGS="$RUSTFLAGS -Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 -Cllvm-args=-sanitizer-coverage-trace-compares -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-trace-geps -Cllvm-args=-sanitizer-coverage-prune-blocks=0 -Cllvm-args=-sanitizer-coverage-pc-table -Clink-dead-code -Cllvm-args=-sanitizer-coverage-stack-depth"
fi
cat $SRC/multiple.txt | while read i; do
    git grep $i | cut -d: -f1 | uniq | xargs sed -i -e s/$i/"$i"_rs/;
done
cargo build
cp ./target/x86_64-unknown-linux-gnu/debug/libhtp.a ../libhtp-rs.a
)

cd libhtp
sh autogen.sh
./configure
make -j$(nproc)

$CC $CFLAGS -I. -c test/fuzz/fuzz_htp.c -o fuzz_htp.o
$CC $CFLAGS -I. -c test/test.c -o test.o
$CXX $CXXFLAGS fuzz_htp.o test.o -o $OUT/fuzz_htp_c ./htp/.libs/libhtp.a $LIB_FUZZING_ENGINE -lz -llzma

$CC $CFLAGS -I. -c test/fuzz/fuzz_diff.c -o fuzz_diff.o
$CXX $CXXFLAGS fuzz_diff.o test.o -o $OUT/fuzz_diff ./htp/.libs/libhtp.a ../libhtp-rs.a $LIB_FUZZING_ENGINE -lz -llzma

# builds corpus
zip -r $OUT/fuzz_htp_seed_corpus.zip test/files/*.t
zip -r $OUT/fuzz_diff_seed_corpus.zip test/files/*.t
