#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

# build project
./autogen.sh
./configure --enable-fuzz-support --enable-never-backslash-C --with-match-limit=1000 --with-match-limit-depth=1000
make -j$(nproc) clean
make -j$(nproc) all

# build fuzzer
$CXX $CXXFLAGS -o $OUT/pcre2_fuzzer \
    $LIB_FUZZING_ENGINE .libs/libpcre2-fuzzsupport.a .libs/libpcre2-8.a

# set up dictionary and options to use it
cp pcre2_fuzzer.options pcre2_fuzzer.dict $OUT/
