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

CXXFLAGS="$CXXFLAGS -O2"

# First, build and install Abseil.
# https://github.com/abseil/abseil-cpp/issues/1524#issuecomment-1739364093
# explains why Abseil must be built for fuzzing, not depended on normally.
# N.B., this is pasted almost verbatim from what libphonenumber does here.
cd $SRC/abseil-cpp
mkdir build && cd build
cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON .. && make -j$(nproc) && make install
ldconfig

# Second, build and install RE2.
# N.B., we don't follow the standard incantation for building RE2
# (i.e., `make && make test && make install && make testinstall`),
# because some of the targets doesn't use $CXXFLAGS properly, which
# causes compilation to fail. The obj/libre2.a target is all we
# really need for our fuzzer, so that's all we build. Hopefully
# this won't cause the fuzzer to fail erroneously due to not running
# upstream's tests first to be sure things compiled correctly.
# However, we do want the "common" files installed so that we can
# interrogate pkg-config about the Abseil dependencies instead of
# maintaining yet another enumeration of them here.
cd $SRC/re2
make -j$(nproc) obj/libre2.a && make common-install

# Third, build the fuzzer (distributed with RE2).
$CXX $CXXFLAGS -I. \
	re2/fuzzing/re2_fuzzer.cc -o $OUT/re2_fuzzer \
	$LIB_FUZZING_ENGINE obj/libre2.a \
	$(pkg-config re2 --libs | sed -e 's/-lre2//')

