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

BUILD=$WORK/build

rm -rf $BUILD
mkdir -p $BUILD

export CFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
export CXXFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -stdlib=libc++"

#cd $SRC/glib-2.64.0
#CC=clang meson _build
#ninja -C _build

#cd $SRC/gdk-pixbuf

#export LD_LIBRARY_PATH="$BUILD/gdk-pixbuf"

CC=clang meson $BUILD
ninja -C $BUILD

#fuzzers=$(find $SRC/gdk-pixbuf/fuzzing/ -name "*_fuzzer.c")
#for f in $fuzzers; do
  #fuzzer_name=$(basename $f .c)
  #ninja -C $BUILD fuzzing/$fuzzer_name
#done

mv $BUILD/fuzzing/*_fuzzer $OUT/
