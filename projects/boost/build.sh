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

# Work around build issue
cp "/usr/local/include/x86_64-unknown-linux-gnu/c++/v1/__config_site" "/usr/local/include/c++/v1/"

# Build boost
CXXFLAGS="$CXXFLAGS -stdlib=libc++ -pthread" LDFLAGS="-stdlib=libc++" \
    ./bootstrap.sh --with-toolset=clang --prefix=/usr;
echo "using clang : ossfuzz : $CXX : <compileflags>\"$CXXFLAGS\" <linkflags>\"$CXXFLAGS\" <linkflags>\"${LIB_FUZZING_ENGINE}\" ;" >user-config.jam
./b2 --user-config=user-config.jam --toolset=clang-ossfuzz link=static --with-headers --with-graph --with-filesystem --with-program_options headers stage;

# Very simple build rule, but sufficient here.
#boost regexp
$CXX $CXXFLAGS -I . ../boost_regex_fuzzer.cc libs/regex/src/*.cpp $LIB_FUZZING_ENGINE -o boost_regex_fuzzer
$CXX $CXXFLAGS -I . ../boost_regex_pattern_fuzzer.cc libs/regex/src/*.cpp $LIB_FUZZING_ENGINE -o boost_regex_pattern_fuzzer
$CXX $CXXFLAGS -I . ../boost_regex_replace_fuzzer.cc libs/regex/src/*.cpp $LIB_FUZZING_ENGINE -o boost_regex_replace_fuzzer

#boost property tree parsers
$CXX $CXXFLAGS -I . ../boost_ptree_xmlread_fuzzer.cc  $LIB_FUZZING_ENGINE -o boost_ptree_xmlread_fuzzer
$CXX $CXXFLAGS -I . ../boost_ptree_jsonread_fuzzer.cc $LIB_FUZZING_ENGINE -o boost_ptree_jsonread_fuzzer
$CXX $CXXFLAGS -I . ../boost_ptree_iniread_fuzzer.cc  $LIB_FUZZING_ENGINE -o boost_ptree_iniread_fuzzer
$CXX $CXXFLAGS -I . ../boost_ptree_inforead_fuzzer.cc $LIB_FUZZING_ENGINE -o boost_ptree_inforead_fuzzer

#boost graph graphviz
$CXX $CXXFLAGS -I . ../boost_graph_graphviz_fuzzer.cc $LIB_FUZZING_ENGINE -o boost_graph_graphviz_fuzzer stage/lib/libboost_graph.a
$CXX $CXXFLAGS -I . ../boost_graph_graphml_fuzzer.cc $LIB_FUZZING_ENGINE -o boost_graph_graphml_fuzzer stage/lib/libboost_graph.a

#boost datetime
$CXX $CXXFLAGS -I . ../boost_datetime_fuzzer.cc $LIB_FUZZING_ENGINE -o boost_datetime_fuzzer

#boost filesystem
$CXX $CXXFLAGS -I . ../boost_filesystem_fuzzer.cc $LIB_FUZZING_ENGINE -o boost_filesystem_fuzzer stage/lib/libboost_filesystem.a

#boost algorithm/strings
$CXX $CXXFLAGS -I . ../boost_stralg_fuzzer.cc $LIB_FUZZING_ENGINE -o boost_stralg_fuzzer

#boost uuid
$CXX $CXXFLAGS -I . ../boost_uuid_fuzzer.cc $LIB_FUZZING_ENGINE -o boost_uuid_fuzzer

#boost programoptions
$CXX $CXXFLAGS -I . ../boost_programoptions_fuzzer.cc $LIB_FUZZING_ENGINE -o boost_programoptions_fuzzer stage/lib/libboost_program_options.a

# Copy the fuzzer executables, zip-ed corpora, option and dictionary files to $OUT
find . -name '*_fuzzer' -exec cp -v '{}' $OUT ';'
# find . -name '*_fuzzer.dict' -exec cp -v '{}' $OUT ';'     # If you have dictionaries.
# find . -name '*_fuzzer.options' -exec cp -v '{}' $OUT ';'  # If you have custom options.
find . -name '*_fuzzer_seed_corpus.zip' -exec cp -v '{}' $OUT ';' # If you have seed corpora (you better have them!)
