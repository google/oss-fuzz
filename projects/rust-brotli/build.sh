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

# checks for integer overflows
export RUSTFLAGS="$RUSTFLAGS -Cdebug-assertions=yes"

cd $SRC/rust-brotli/fuzz
cargo fuzz build
cp $SRC/rust-brotli/fuzz/target/x86_64-unknown-linux-gnu/release/decompress $OUT/
cp $SRC/rust-brotli/fuzz/target/x86_64-unknown-linux-gnu/release/roundtrip $OUT/
