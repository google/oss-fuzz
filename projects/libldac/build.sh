#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

$CC $CFLAGS -Iinc -c $SRC/libldac_encode_fuzzer.cc -o libldac_encode_fuzzer.o
$CC $CFLAGS -Iinc -c src/ldaclib.c -o src/ldaclib.o
$CC $CFLAGS -Iinc -c src/ldacBT.c -o src/ldacBT.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
	libldac_encode_fuzzer.o \
	src/ldaclib.o \
	src/ldacBT.o \
	-o $OUT/libldac_encode_fuzzer

zip -q $OUT/libldac_encode_fuzzer_seed_corpus.zip $SRC/corpora/*
