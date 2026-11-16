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

export LLVM_SYS_231_PREFIX=$($SRC/.llvm/bin/llvm-config --prefix)

# Needed for coverage to work.
nightly="+$RUSTUP_TOOLCHAIN"

cargo $nightly fuzz build cranelift --features=cranelift,sanitizer -O
cargo $nightly fuzz build llvm --features=llvm,sanitizer -O
cargo $nightly fuzz build singlepass --features=singlepass,sanitizer -O
cargo $nightly fuzz build metering --features=cranelift,sanitizer -O
cargo $nightly fuzz build deterministic --features=cranelift,llvm,singlepass,sanitizer -O

fuzz_targets="cranelift \
  llvm \
  singlepass \
  metering \
  deterministic"
fuzz_target_output_dir=target/x86_64-unknown-linux-gnu/release

for target in $fuzz_targets; do
	cp $fuzz_target_output_dir/$target $OUT/
	cp $SRC/default.options $OUT/$target.options
done
