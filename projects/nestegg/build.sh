#!/bin/bash -eu
# Copyright 2024 Google Inc.
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

$CC $CFLAGS -c -I./include src/nestegg.c
$CXX $CXXFLAGS -o $OUT/fuzz -I./include nestegg.o test/fuzz.cc $LIB_FUZZING_ENGINE


mkdir corpus/
# copy libwebm test data
cp -R ../libwebm/testing/testdata/*.webm corpus/
# copy nestegg test data
cp test/media/*.webm corpus/
zip -rj0 $OUT/fuzz_seed_corpus.zip corpus/*.webm
