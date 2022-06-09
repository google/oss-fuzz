#!/bin/bash -eu
# Copyright 2021 Google LLC
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

# Build CMake.
mkdir build-dir && cd build-dir
../bootstrap && make -j$(nproc)


# Build fuzzers.
cd ../Tests/Fuzzing
$CXX $CXXFLAGS -I../../Source \
	-I../../build-dir/Source \
	-c xml_parser_fuzzer.cc \
	-o xml_parser_fuzzer.o 


export cmexpat_dir="${SRC}/CMake/build-dir/Utilities/cmexpat/CMakeFiles/cmexpat.dir/lib"
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
		xml_parser_fuzzer.o -o $OUT/xml_parser_fuzzer \
		../../build-dir/Source/CMakeFiles/CMakeLib.dir/cmXMLParser.cxx.o \
		$cmexpat_dir/xmlparse.c.o \
		$cmexpat_dir/xmlrole.c.o \
		$cmexpat_dir/xmltok.c.o	


# Build seed corpus
zip $OUT/xml_parser_fuzzer_seed_corpus.zip $SRC/fuzzing-corpus/xml/test.xml
