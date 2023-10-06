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

cd $SRC/connectedhomeip

# Activate Pigweed environment
set +u
PW_ENVSETUP_QUIET=1 source scripts/activate.sh
set -u

# Create a build directory with the following options:
# - `oss_fuzz` enables OSS-Fuzz build
# - `is_clang` selects clang toolchains (does not support AFL fuzzing engine)
# - `enable_rrti` enables RTTI to support UBSan build
# - `chip_enable_thread_safety_checks` disabled since OSS-Fuzz clang does not
#   seem to currently support or need this analysis
# - `target_ldflags` forces compiler to use LLVM's linker
gn gen out/fuzz_targets \
  --args="
    oss_fuzz=true \
    is_clang=true \
    enable_rtti=true \
    chip_enable_thread_safety_checks=false \
    target_ldflags=[\"-fuse-ld=lld\"]"

# Deactivate Pigweed environment to use OSS-Fuzz toolchains
deactivate

# Compile fuzz targets
ninja -C out/fuzz_targets fuzz_tests

cp out/fuzz_targets/tests/* $OUT/
