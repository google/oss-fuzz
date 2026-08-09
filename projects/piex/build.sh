#!/bin/bash -eu
# Copyright 2025 Google LLC
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


$CXX $CXXFLAGS $CFLAGS  -I. \
    -c $SRC/piex/src/binary_parse/cached_paged_byte_array.cc \
       -o cached_paged_byte_array.o &
$CXX $CXXFLAGS $CFLAGS  -I. \
    -c $SRC/piex/src/binary_parse/range_checked_byte_ptr.cc \
       -o range_checked_byte_ptr.o &

wait

ar rcs libbinary_parse.a \
    cached_paged_byte_array.o range_checked_byte_ptr.o

$CXX $CXXFLAGS $CFLAGS  -I. \
    -c $SRC/piex/src/image_type_recognition/image_type_recognition_lite.cc \
       -o image_type_recognition_lite.o
ar rcs libimage_type_recognition.a image_type_recognition_lite.o

$CXX $CXXFLAGS $CFLAGS  -I. \
    -c $SRC/piex/src/tiff_directory/tiff_directory.cc \
       -o tiff_directory.o
ar rcs libtiff_directory.a tiff_directory.o


$CXX $CXXFLAGS $CFLAGS  -I. \
    -c $SRC/piex/src/piex.cc -o piex.o &
$CXX $CXXFLAGS $CFLAGS  -I. \
    -c $SRC/piex/src/piex_cr3.cc -o piex_cr3.o &
$CXX $CXXFLAGS $CFLAGS  -I. \
    -c $SRC/piex/src/tiff_parser.cc -o tiff_parser.o &
wait
ar rcs libpiex.a piex.o piex_cr3.o tiff_parser.o

$CXX $CXXFLAGS $CFLAGS -I. $SRC/piex/src/piex_fuzzer.cc libpiex.a libtiff_directory.a \
    libimage_type_recognition.a libbinary_parse.a $LIB_FUZZING_ENGINE -o $OUT/fuzzer-piex
cp $SRC/old-build/*_seed_corpus.zip $OUT
