#!/bin/bash -eu
# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by ap plicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

export LLVM_SYS_120_PREFIX=$(llvm-config-12 --prefix)

cargo +nightly fuzz build universal_cranelift --features=universal,cranelift -O
cargo +nightly fuzz build universal_llvm --features=universal,llvm -O
cargo +nightly fuzz build universal_singlepass --features=universal,singlepass -O
cargo +nightly fuzz build metering --features=universal,cranelift -O
cargo +nightly fuzz build deterministic --features=universal,cranelift,llvm,singlepass -O

fuzz_targets="universal_cranelift \
  universal_llvm \
  universal_singlepass \
  metering \
  deterministic"
fuzz_target_output_dir=target/x86_64-unknown-linux-gnu/release

for target in $fuzz_targets
do
  cp $fuzz_target_output_dir/$target $OUT/
  cp $SRC/default.options $OUT/$target.options
done
