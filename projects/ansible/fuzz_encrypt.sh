#!/bin/sh
# Copyright 2022 Google LLC.
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

# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=$(dirname "$0")
chmod +x $this_dir/fuzz_encrypt.pkg
LD_PRELOAD="$this_dir/sanitizer_with_fuzzer.so $this_dir/libcrypt.so" ASAN_OPTIONS=$ASAN_OPTIONS:symbolize=1:external_symbolizer_path=$this_dir/llvm-symbolizer:detect_leaks=0 $this_dir/fuzz_encrypt.pkg $@
