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
$SRC/depot_tools/gn gen out/Fuzz_mem_constraints\
    --args='cc="'$CC'"
    cxx="'$CXX'"
    is_debug=false
    extra_cflags=["'"$CXXFLAGS_ARR"'","-DIS_FUZZING","-DIS_FUZZING_WITH_LIBFUZZER",
        "-Wno-zero-as-null-pointer-constant", "-Wno-unused-template", "-Wno-cast-qual"]
    skia_use_system_freetype2=false
    skia_use_fontconfig=false
    skia_enable_gpu=false
    extra_ldflags=["-lFuzzingEngine", "'"$CXXFLAGS_ARR"'"]'

$SRC/depot_tools/gn gen out/Fuzz\
    --args='cc="'$CC'"
    cxx="'$CXX'"
    is_debug=false
    extra_cflags=["'"$CXXFLAGS_ARR"'","-DIS_FUZZING_WITH_LIBFUZZER",
        "-Wno-zero-as-null-pointer-constant", "-Wno-unused-template", "-Wno-cast-qual"]
    skia_use_system_freetype2=false
    skia_use_fontconfig=false
    skia_enable_gpu=false
    extra_ldflags=["-lFuzzingEngine", "'"$CXXFLAGS_ARR"'"]'

$SRC/depot_tools/gn gen out/GPU\
    --args='cc="'$CC'"
    cxx="'$CXX'"
    is_debug=false
    extra_cflags=["'"$CXXFLAGS_ARR"'","-DIS_FUZZING","-DIS_FUZZING_WITH_LIBFUZZER",
        "-Wno-zero-as-null-pointer-constant", "-Wno-unused-template", "-Wno-cast-qual"]
    skia_use_system_freetype2=false
    skia_use_fontconfig=false
    skia_enable_gpu=true
    extra_ldflags=["-lFuzzingEngine", "'"$CXXFLAGS_ARR"'"]'

$SRC/depot_tools/ninja -C out/Fuzz_mem_constraints image_filter_deserialize \
                                                   textblob_deserialize api_raster_n32_canvas

$SRC/depot_tools/ninja -C out/Fuzz region_deserialize region_set_path \
                                   path_deserialize image_decode animated_image_decode \
                                   api_draw_functions api_gradients api_image_filter \
                                   api_path_measure api_null_canvas png_encoder \
                                   jpeg_encoder webp_encoder

$SRC/depot_tools/ninja -C out/GPU api_null_gl_canvas

cp out/Fuzz/region_deserialize $OUT/region_deserialize
cp ./region_deserialize.options $OUT/region_deserialize.options

cp out/Fuzz/region_set_path $OUT/region_set_path
cp ./region_set_path.options $OUT/region_set_path.options
cp ./region_set_path_seed_corpus.zip $OUT/region_set_path_seed_corpus.zip

cp out/Fuzz_mem_constraints/textblob_deserialize $OUT/textblob_deserialize
cp ./textblob_deserialize.options $OUT/textblob_deserialize.options
cp ./textblob_deserialize_seed_corpus.zip $OUT/textblob_deserialize_seed_corpus.zip

cp out/Fuzz/path_deserialize $OUT/path_deserialize
cp ./path_deserialize.options $OUT/path_deserialize.options
cp ./path_deserialize_seed_corpus.zip $OUT/path_deserialize_seed_corpus.zip

cp out/Fuzz/image_decode $OUT/image_decode
cp ./image_decode.options $OUT/image_decode.options
cp ./image_decode_seed_corpus.zip $OUT/image_decode_seed_corpus.zip

cp out/Fuzz/animated_image_decode $OUT/animated_image_decode
cp ./animated_image_decode.options $OUT/animated_image_decode.options
cp ./animated_image_decode_seed_corpus.zip $OUT/animated_image_decode_seed_corpus.zip

cp out/Fuzz_mem_constraints/image_filter_deserialize $OUT/image_filter_deserialize
cp ./image_filter_deserialize.options $OUT/image_filter_deserialize.options
cp ./image_filter_deserialize_seed_corpus.zip $OUT/image_filter_deserialize_seed_corpus.zip

# Only create the width version of image_filter_desrialize if building with
# libfuzzer, since it depends on a libfuzzer specific flag.
if [ "$FUZZING_ENGINE" == "libfuzzer" ]
then
  # Use the same binary as image_filter_deserialize.
  cp out/Fuzz_mem_constraints/image_filter_deserialize $OUT/image_filter_deserialize_width
  cp ./image_filter_deserialize_width.options $OUT/image_filter_deserialize_width.options
  # Use the same seed corpus as image_filter_deserialize.
  cp ./image_filter_deserialize_seed_corpus.zip $OUT/image_filter_deserialize_width_seed_corpus.zip
fi

cp out/Fuzz/api_draw_functions $OUT/api_draw_functions
cp ./api_draw_functions.options $OUT/api_draw_functions.options
cp ./api_draw_functions_seed_corpus.zip $OUT/api_draw_functions_seed_corpus.zip

cp out/Fuzz/api_gradients $OUT/api_gradients
cp ./api_gradients.options $OUT/api_gradients.options
cp ./api_gradients_seed_corpus.zip $OUT/api_gradients_seed_corpus.zip

cp out/Fuzz/api_image_filter $OUT/api_image_filter
cp ./api_image_filter.options $OUT/api_image_filter.options
cp ./api_image_filter_seed_corpus.zip $OUT/api_image_filter_seed_corpus.zip

cp out/Fuzz/api_path_measure $OUT/api_path_measure
cp ./api_path_measure.options $OUT/api_path_measure.options
cp ./api_path_measure_seed_corpus.zip $OUT/api_path_measure_seed_corpus.zip

cp out/Fuzz_mem_constraints/api_raster_n32_canvas $OUT/api_raster_n32_canvas
cp ./api_raster_n32_canvas.options $OUT/api_raster_n32_canvas.options
cp ./canvas_seed_corpus.zip $OUT/api_raster_n32_canvas_seed_corpus.zip

cp out/Fuzz/api_null_canvas $OUT/api_null_canvas
cp ./api_null_canvas.options $OUT/api_null_canvas.options
cp ./canvas_seed_corpus.zip $OUT/api_null_canvas_seed_corpus.zip

# Remove unnecessary dependencies that aren't on runner containers.
# Libraries found through trial and error (ldd command also helpful).
patchelf --remove-needed libGLU.so.1 out/GPU/api_null_gl_canvas
patchelf --remove-needed libGL.so.1 out/GPU/api_null_gl_canvas
patchelf --remove-needed libX11.so.6 out/GPU/api_null_gl_canvas
cp out/GPU/api_null_gl_canvas $OUT/api_null_gl_canvas

cp out/Fuzz/png_encoder $OUT/png_encoder
cp ./encoder.options $OUT/png_encoder.options
cp ./encoder_seed_corpus.zip $OUT/png_encoder_seed_corpus.zip

cp out/Fuzz/jpeg_encoder $OUT/jpeg_encoder
cp ./encoder.options $OUT/jpeg_encoder.options
cp ./encoder_seed_corpus.zip $OUT/jpeg_encoder_seed_corpus.zip

cp out/Fuzz/webp_encoder $OUT/webp_encoder
cp ./encoder.options $OUT/webp_encoder.options
cp ./encoder_seed_corpus.zip $OUT/webp_encoder_seed_corpus.zip

