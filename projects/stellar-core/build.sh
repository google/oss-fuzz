#!/bin/bash -eu
# Copyright 2026 Google LLC
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

. "$HOME/.cargo/env"
./autogen.sh

# NB: the oss-fuzz driver injects sanitizer flags to CFLAGS, CXXFLAGS
# and RUSTFLAGS. This overlaps with our own support for sanitizers,
# but not fatally. It does require us to enable the unified rust
# build.
./configure --enable-fuzz --enable-unified-rust-unsafe-for-production --disable-postgres
make -j $(nproc)
make -C src fuzz-targets
cp src/fuzz_* $OUT
