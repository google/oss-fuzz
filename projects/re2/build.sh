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

# First, build RE2.
# N.B., we don't follow the standard incantation for building RE2
# (i.e., `make && make test && make install && make testinstall`),
# because some of the targets doesn't use $CXXFLAGS properly, which
# causes compilation to fail. The obj/libre2.a target is all we
# really need for our fuzzer, so that's all we build. Hopefully
# this won't cause the fuzzer to fail erroneously due to not running
# upstream's tests first to be sure things compiled correctly.
CXXFLAGS="$CXXFLAGS -O2"
make clean
make -j$(nproc) obj/libre2.a

# Second, build the fuzzer (distributed with RE2).
$CXX $CXXFLAGS -std=c++11 -I. \
	re2/fuzzing/re2_fuzzer.cc -o $OUT/re2_fuzzer \
	$LIB_FUZZING_ENGINE obj/libre2.a
