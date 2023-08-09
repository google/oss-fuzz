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
################################################################################

# build fuzz targets
cd $SRC/opendal/core
cargo +nightly fuzz build -O --debug-assertions

# copy fuzz targets to $OUT
targets=(
  fuzz_reader
  fuzz_writer
)

cp $SRC/.fs.env $OUT/.fs.env
cp ../target/x86_64-unknown-linux-gnu/release/fuzz_reader $OUT/fuzz_reader_fs
cp ../target/x86_64-unknown-linux-gnu/release/fuzz_reader $OUT/fuzz_writer_fs

cp $SRC/.memory.env $OUT/.memory.env
cp ../target/x86_64-unknown-linux-gnu/release/fuzz_reader $OUT/fuzz_reader_memory
cp ../target/x86_64-unknown-linux-gnu/release/fuzz_reader $OUT/fuzz_writer_memory

