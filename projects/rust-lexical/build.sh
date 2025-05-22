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
cd $SRC/rust-lexical/fuzz
cargo fuzz build -O
cp $SRC/rust-lexical/fuzz/target/x86_64-unknown-linux-gnu/release/parse-integer-i8 $OUT/
cp $SRC/rust-lexical/fuzz/target/x86_64-unknown-linux-gnu/release/parse-integer-i16 $OUT/
cp $SRC/rust-lexical/fuzz/target/x86_64-unknown-linux-gnu/release/parse-integer-i32 $OUT/
cp $SRC/rust-lexical/fuzz/target/x86_64-unknown-linux-gnu/release/parse-integer-i64 $OUT/
cp $SRC/rust-lexical/fuzz/target/x86_64-unknown-linux-gnu/release/parse-integer-i128 $OUT/
cp $SRC/rust-lexical/fuzz/target/x86_64-unknown-linux-gnu/release/parse-integer-isize $OUT/
cp $SRC/rust-lexical/fuzz/target/x86_64-unknown-linux-gnu/release/parse-integer-u8 $OUT/
cp $SRC/rust-lexical/fuzz/target/x86_64-unknown-linux-gnu/release/parse-integer-u16 $OUT/
cp $SRC/rust-lexical/fuzz/target/x86_64-unknown-linux-gnu/release/parse-integer-u32 $OUT/
cp $SRC/rust-lexical/fuzz/target/x86_64-unknown-linux-gnu/release/parse-integer-u64 $OUT/
cp $SRC/rust-lexical/fuzz/target/x86_64-unknown-linux-gnu/release/parse-integer-u128 $OUT/
cp $SRC/rust-lexical/fuzz/target/x86_64-unknown-linux-gnu/release/parse-integer-usize $OUT/
cp $SRC/rust-lexical/fuzz/target/x86_64-unknown-linux-gnu/release/parse-float-f32 $OUT/
cp $SRC/rust-lexical/fuzz/target/x86_64-unknown-linux-gnu/release/parse-float-f64 $OUT/
cp $SRC/rust-lexical/fuzz/target/x86_64-unknown-linux-gnu/release/write-float-f32 $OUT/
cp $SRC/rust-lexical/fuzz/target/x86_64-unknown-linux-gnu/release/write-float-f64 $OUT/
cp $SRC/rust-lexical/fuzz/target/x86_64-unknown-linux-gnu/release/write-integer-i8 $OUT/
cp $SRC/rust-lexical/fuzz/target/x86_64-unknown-linux-gnu/release/write-integer-i16 $OUT/
cp $SRC/rust-lexical/fuzz/target/x86_64-unknown-linux-gnu/release/write-integer-i32 $OUT/
cp $SRC/rust-lexical/fuzz/target/x86_64-unknown-linux-gnu/release/write-integer-i64 $OUT/
cp $SRC/rust-lexical/fuzz/target/x86_64-unknown-linux-gnu/release/write-integer-i128 $OUT/
cp $SRC/rust-lexical/fuzz/target/x86_64-unknown-linux-gnu/release/write-integer-isize $OUT/
cp $SRC/rust-lexical/fuzz/target/x86_64-unknown-linux-gnu/release/write-integer-u8 $OUT/
cp $SRC/rust-lexical/fuzz/target/x86_64-unknown-linux-gnu/release/write-integer-u16 $OUT/
cp $SRC/rust-lexical/fuzz/target/x86_64-unknown-linux-gnu/release/write-integer-u32 $OUT/
cp $SRC/rust-lexical/fuzz/target/x86_64-unknown-linux-gnu/release/write-integer-u64 $OUT/
cp $SRC/rust-lexical/fuzz/target/x86_64-unknown-linux-gnu/release/write-integer-u128 $OUT/
cp $SRC/rust-lexical/fuzz/target/x86_64-unknown-linux-gnu/release/write-integer-usize $OUT/