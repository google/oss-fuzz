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

# OSS-Fuzz entrypoint: build every fuzz target and copy the binaries to $OUT.
# Lives at projects/verdigris/build.sh in google/oss-fuzz.
cd $SRC/verdigris/fuzz

if [ "$SANITIZER" = "coverage" ]; then
  export RUSTFLAGS="$RUSTFLAGS -C debug-assertions=no"
  export CFLAGS=""
fi

cargo fuzz build -O --debug-assertions

for target in config_parse path_normalize route_match cache_index \
              http_semantics headers_policy static_resolve; do
    cp target/x86_64-unknown-linux-gnu/release/$target $OUT/
done
