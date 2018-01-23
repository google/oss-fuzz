#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

# Disable UBSan vptr since target built with -fno-rtti.
export CFLAGS="$CFLAGS -fno-sanitize=vptr"
export CXXFLAGS="$CXXFLAGS -fno-sanitize=vptr"

# This splits a space separated list into a quoted, comma separated list for gn.
export CXXFLAGS_ARR=`echo $CXXFLAGS | sed -e "s/\s/\",\"/g"`
$SRC/depot_tools/gn gen out/Fuzz\
    --args='cc="'$CC'"
    cxx="'$CXX'"
    is_debug=false
    extra_cflags=["'"$CXXFLAGS_ARR"'","-DIS_FUZZING","-DIS_FUZZING_WITH_LIBFUZZER",
        "-Wno-zero-as-null-pointer-constant", "-Wno-unused-template", "-Wno-cast-qual"]
    skia_use_system_freetype2=false
    skia_use_fontconfig=false
    skia_enable_gpu=false
    extra_ldflags=["-lFuzzingEngine", "'"$CXXFLAGS_ARR"'"]'

$SRC/depot_tools/ninja -C out/Fuzz fuzz_region_deserialize image_filter_deserialize

cp out/Fuzz/fuzz_region_deserialize $OUT/region_deserialize
cp ./region_deserialize.options $OUT/region_deserialize.options

cp out/Fuzz/image_filter_deserialize $OUT/image_filter_deserialize
cp ./image_filter_deserialize.options $OUT/image_filter_deserialize.options
cp ./image_filter_deserialize_seed_corpus.zip $OUT/image_filter_deserialize_seed_corpus.zip
