#!/bin/bash -eu
# Copyright 2017 Google Inc.
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

# Build boost
CXXFLAGS="$CXXFLAGS -stdlib=libc++ -pthread" LDFLAGS="-stdlib=libc++" \
    ./bootstrap.sh --with-toolset=clang --prefix=/usr;
./b2 toolset=clang cxxflags="$CXXFLAGS -stdlib=libc++ -pthread" linkflags="-stdlib=libc++ -pthread" headers;

# Very simple build rule, but sufficient here.
#boost regexp
$CXX $CXXFLAGS -I . ../boost_regex_fuzzer.cc libs/regex/src/*.cpp $LIB_FUZZING_ENGINE -o boost_regex_fuzzer

#boost property tree parsers
$CXX $CXXFLAGS -I . ../boost_ptree_xmlread_fuzzer.cc  $LIB_FUZZING_ENGINE -o boost_ptree_xmlread_fuzzer
$CXX $CXXFLAGS -I . ../boost_ptree_jsonread_fuzzer.cc $LIB_FUZZING_ENGINE -o boost_ptree_jsonread_fuzzer
$CXX $CXXFLAGS -I . ../boost_ptree_iniread_fuzzer.cc  $LIB_FUZZING_ENGINE -o boost_ptree_iniread_fuzzer
$CXX $CXXFLAGS -I . ../boost_ptree_inforead_fuzzer.cc $LIB_FUZZING_ENGINE -o boost_ptree_inforead_fuzzer

# Copy the fuzzer executables, zip-ed corpora, option and dictionary files to $OUT
find . -name '*_fuzzer' -exec cp -v '{}' $OUT ';'
# find . -name '*_fuzzer.dict' -exec cp -v '{}' $OUT ';'     # If you have dictionaries.
# find . -name '*_fuzzer.options' -exec cp -v '{}' $OUT ';'  # If you have custom options.
# find . -name '*_fuzzer_seed_corpus.zip' -exec cp -v '{}' $OUT ';' # If you have seed corpora (you better have them!)
