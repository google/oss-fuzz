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
################################################################################
cd $SRC/textwrap/fuzz
cargo fuzz build
cp $SRC/textwrap/fuzz/target/x86_64-unknown-linux-gnu/release/fill_fast_path $OUT/
cp $SRC/textwrap/fuzz/target/x86_64-unknown-linux-gnu/release/fill_first_fit $OUT/
cp $SRC/textwrap/fuzz/target/x86_64-unknown-linux-gnu/release/fill_optimal_fit $OUT/
cp $SRC/textwrap/fuzz/target/x86_64-unknown-linux-gnu/release/refill $OUT/
cp $SRC/textwrap/fuzz/target/x86_64-unknown-linux-gnu/release/unfill $OUT/
cp $SRC/textwrap/fuzz/target/x86_64-unknown-linux-gnu/release/wrap_fast_path $OUT/
cp $SRC/textwrap/fuzz/target/x86_64-unknown-linux-gnu/release/wrap_first_fit $OUT/
cp $SRC/textwrap/fuzz/target/x86_64-unknown-linux-gnu/release/wrap_optimal_fit $OUT/
cp $SRC/textwrap/fuzz/target/x86_64-unknown-linux-gnu/release/wrap_optimal_fit_usize $OUT/
