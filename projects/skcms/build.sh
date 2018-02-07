#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

echo "hello world"

$CC -c $CFLAGS skcms.c iccprofile_parse.c iccprofile_atf.c
$CXX $CXXFLAGS skcms.o iccprofile_parse.o $LIB_FUZZING_ENGINE -o $OUT/iccprofile_parse
$CXX $CXXFLAGS skcms.o iccprofile_atf.o $LIB_FUZZING_ENGINE -o $OUT/iccprofile_atf

# They share the same options
cp iccprofile.options $OUT/iccprofile_parse.options
cp iccprofile.options $OUT/iccprofile_atf.options
# They all share the same seed corpus of icc profiles
cp iccprofile_parse_seed_corpus.zip $OUT/iccprofile_parse_seed_corpus.zip
cp iccprofile_parse_seed_corpus.zip $OUT/iccprofile_atf_seed_corpus.zip