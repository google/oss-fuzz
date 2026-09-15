#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

# Configure Test Data Path
export GRK_DATA_ROOT=$SRC/grok-data

# An explicit cargo target keeps RUSTFLAGS off build scripts and proc
# macros, which rustc cannot load when instrumented.
export CARGO_BUILD_TARGET="$(rustc -vV | sed -n 's/host: //p')"

# mercury (rust) would need an msan-instrumented rust std, which this build
# cannot provide, so msan disables mercury and the mercury fuzzer exercises
# the c++ fallback path. Other sanitizers inherit -Zsanitizer from the
# RUSTFLAGS exported by the compile script; libfuzzer builds also add sancov
# so the fuzzer gets coverage feedback inside the rust code.
MERCURY_CMAKE_ARGS=""
if [ "$SANITIZER" = "memory" ]; then
    MERCURY_CMAKE_ARGS="-DCARGO_EXECUTABLE=/bin/false"
elif [ "${FUZZING_ENGINE:-}" = "libfuzzer" ]; then
    if [ "$SANITIZER" = "address" ] || [ "$SANITIZER" = "undefined" ]; then
        export RUSTFLAGS="${RUSTFLAGS:-} -Cpasses=sancov-module \
            -Cllvm-args=-sanitizer-coverage-level=4 \
            -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
            -Cllvm-args=-sanitizer-coverage-pc-table \
            -Cllvm-args=-sanitizer-coverage-trace-compares"
    fi
fi

# Build grok core code and unit test
mkdir build
cd build
cmake .. -DGRK_BUILD_CODEC=ON -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=ON $MERCURY_CMAKE_ARGS
make clean -s
make -j$(nproc) -s
cd ..

./tests/fuzzers/build_google_oss_fuzzers.sh
./tests/fuzzers/build_seed_corpus.sh
