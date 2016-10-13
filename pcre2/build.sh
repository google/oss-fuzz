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

cd /src/pcre2
svn co svn://vcs.exim.org/pcre2/code/trunk pcre2
cd pcre2

# build the library.
./autogen.sh
SAVED_LDFLAGS="$LDFLAGS"
export LDFLAGS=  # Can't use provided LDFLAGS to build pcre's .a targets.
./configure --enable-never-backslash-C --with-match-limit=1000 --with-match-limit-recursion=1000
make clean all

# Build the target.
$CXX $CXXFLAGS -std=c++11 -I src  \
     /src/pcre2_fuzzer.cc -o /out/pcre2_fuzzer \
     -Wl,--whole-archive .libs/*.a -Wl,-no-whole-archive $SAVED_LDFLAGS \
     /work/libfuzzer/*.o
