#!/bin/bash -eux
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

# Note: This project creates Rust fuzz targets exclusively

# recipe:
# -------
# 1. we list all the fuzzers and save to a file fuzzer_list
# 2. we build the corpus for each fuzzer
# 3. we build all the fuzzers

# reset flags of OSS-Fuzz
export CFLAGS="-fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
export CXXFLAGS_EXTRA="-stdlib=libc++"
export CXXFLAGS="$CFLAGS $CXXFLAGS_EXTRA"

# correct workdir
cd $SRC/libra/testsuite/libra-fuzzer

# execute the build script
chmod +x fuzz/google-oss-fuzz/build.sh
./fuzz/google-oss-fuzz/build.sh
