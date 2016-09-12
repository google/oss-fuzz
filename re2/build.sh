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

cd /src/re2

function _start()   { echo -e "\n\033[1;33m➜\033[0m \033[1m$*\033[0m"; }
function _success() { echo -e "\033[1;32m✔\033[0m \033[1m$*\033[0m"; }
function _failure() { echo -e "\n\033[1;31m✖\033[0m \033[1m$*\033[0m"; }

function _try() {
	_start "$*"
	$@
	if [ $? -eq 0 ]; then
		_success "$*"
	else
		_failure "$*"
		exit $?
	fi
}


# First, build the re2 library.
# N.B., we don't follow the standard incantation for building re2
# (i.e., `make && make test && make install && make testinstall`),
# because some of the targets doesn't use $CXXFLAGS properly, which
# causes compilation to fail. The obj/libre2.a target is all we
# really need for our fuzzer, so that's all we build. Hopefully
# this won't cause the fuzzer to fail erroneously due to not running
# upstream's tests first to be sure things compiled correctly.
_try make clean
_try make obj/libre2.a


# Second, build our fuzzers.
_try $CXX $CXXFLAGS -std=c++11 -I. \
	/src/oss-fuzz/re2/re2_fuzzer.cc -o /out/re2_fuzzer \
	/work/libfuzzer/*.o ./obj/libre2.a $LDFLAGS

