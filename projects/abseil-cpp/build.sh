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

#Compiling and building dependencies
mkdir -p build
cd build
cmake -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
	-DBUILD_SHARED_LIBS=OFF -G "Unix Makefiles" ..
make
#Building string_escape_fuzzer
$CXX $CXXFLAGS -I../ \
	$SRC/string_escape_fuzzer.cc -o $OUT/string_escape_fuzzer \
	$LIB_FUZZING_ENGINE \
	absl/strings/libabsl_strings.a \
	absl/numeric/libabsl_int128.a \
	absl/strings/libabsl_strings_internal.a \
	absl/base/libabsl_base.a \
	absl/base/libabsl_throw_delegate.a \
	absl/base/libabsl_raw_logging_internal.a

#Building string_utilities_fuzzer
$CXX $CXXFLAGS -I../ \
	$SRC/string_utilities_fuzzer.cc -o $OUT/string_utilities_fuzzer \
	$LIB_FUZZING_ENGINE \
	absl/strings/libabsl_strings.a \
	absl/numeric/libabsl_int128.a \
	absl/strings/libabsl_strings_internal.a \
	absl/base/libabsl_base.a \
	absl/base/libabsl_throw_delegate.a \
	absl/base/libabsl_raw_logging_internal.a