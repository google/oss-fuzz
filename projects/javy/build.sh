#!/bin/bash -eu

# Copyright 2024 Google LLC
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

# Using `--sanitizer none` because other sanitizers seem to cause out of memory errors
# Setting `-fno-sanitize=all` since I see undefined references to `__sancov_gen_` if I don't
CFLAGS="$CFLAGS -fno-sanitize=all" RUSTFLAGS="-C link-arg=-fno-sanitize=all" cargo fuzz build --sanitizer none
cp target/x86_64-unknown-linux-gnu/release/json-differential $OUT/json-differential
