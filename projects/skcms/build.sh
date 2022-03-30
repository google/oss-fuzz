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

$CXX -c $CXXFLAGS skcms.cc -DIS_FUZZING_WITH_LIBFUZZER
$CC -c $CFLAGS fuzz/fuzz_iccprofile_info.c fuzz/fuzz_iccprofile_atf.c fuzz/fuzz_iccprofile_transform.c -DIS_FUZZING_WITH_LIBFUZZER
$CXX $CXXFLAGS skcms.o fuzz_iccprofile_info.o $LIB_FUZZING_ENGINE -o $OUT/iccprofile_info
$CXX $CXXFLAGS skcms.o fuzz_iccprofile_atf.o $LIB_FUZZING_ENGINE -o $OUT/iccprofile_atf
$CXX $CXXFLAGS skcms.o fuzz_iccprofile_transform.o $LIB_FUZZING_ENGINE -o $OUT/iccprofile_transform

# They share the same options
cp iccprofile.options $OUT/iccprofile_info.options
cp iccprofile.options $OUT/iccprofile_atf.options
cp iccprofile.options $OUT/fuzz_iccprofile_transform.options
# They all share the same seed corpus of icc profiles
cp iccprofile_seed_corpus.zip $OUT/iccprofile_info_seed_corpus.zip
cp iccprofile_seed_corpus.zip $OUT/iccprofile_atf_seed_corpus.zip
cp iccprofile_seed_corpus.zip $OUT/iccprofile_transform_seed_corpus.zip
# They all use the same dictionary file.
cp iccprofile.dict $OUT/iccprofile.dict
