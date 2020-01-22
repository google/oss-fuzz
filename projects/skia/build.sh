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

# Build SwiftShader
pushd third_party/externals/swiftshader/
export SWIFTSHADER_INCLUDE_PATH=$PWD/include
rm -rf build
mkdir build

cd build
if [ $SANITIZER == "coverage" ]; then
  cmake ..
else
  if [ $SANITIZER == "address" ]; then
    CMAKE_SANITIZER="ASAN"
  elif [ $SANITIZER == "memory" ]; then
    CMAKE_SANITIZER="MSAN"
  elif [ $SANITIZER == "undefined" ]; then
    CMAKE_SANITIZER="UBSAN"
  else
    exit 1
  fi
  CFLAGS= CXXFLAGS="-stdlib=libc++" cmake .. -D$CMAKE_SANITIZER=1
fi

make -j
cp libGLESv2.so libEGL.so $OUT
export SWIFTSHADER_LIB_PATH=$OUT

popd
# These are any clang warnings we need to silence.
DISABLE="-Wno-zero-as-null-pointer-constant -Wno-unused-template
         -Wno-cast-qual"
# Disable UBSan vptr since target built with -fno-rtti.
# TODO(metzman): Stop using gold when
# bugs.chromium.org/p/oss-fuzz/issues/detail?id=16777 gets resolved.
export CFLAGS="$CFLAGS $DISABLE -I$SWIFTSHADER_INCLUDE_PATH -DGR_EGL_TRY_GLES3_THEN_GLES2 -fno-sanitize=vptr"
export CXXFLAGS="$CXXFLAGS $DISABLE -I$SWIFTSHADER_INCLUDE_PATH -DGR_EGL_TRY_GLES3_THEN_GLES2 -fno-sanitize=vptr "-DIS_FUZZING_WITH_LIBFUZZER""
export LDFLAGS="$LIB_FUZZING_ENGINE $CXXFLAGS -L$SWIFTSHADER_LIB_PATH -fuse-ld=gold"

# This splits a space separated list into a quoted, comma separated list for gn.
export CFLAGS_ARR=`echo $CFLAGS | sed -e "s/\s/\",\"/g"`
export CXXFLAGS_ARR=`echo $CXXFLAGS | sed -e "s/\s/\",\"/g"`
export LDFLAGS_ARR=`echo $LDFLAGS | sed -e "s/\s/\",\"/g"`

# Even though GPU is "enabled" for all these builds, none really
# uses the gpu except for api_mock_gpu_canvas

$SRC/depot_tools/gn gen out/Fuzz\
    --args='cc="'$CC'"
      cxx="'$CXX'"
      is_debug=false
      extra_cflags_c=["'"$CFLAGS_ARR"'"]
      extra_cflags_cc=["'"$CXXFLAGS_ARR"'"]
      extra_ldflags=["'"$LDFLAGS_ARR"'"]
      skia_enable_fontmgr_custom=false
      skia_enable_fontmgr_custom_empty=true
      skia_enable_gpu=true
      skia_enable_skottie=true
      skia_use_egl=true
      skia_use_fontconfig=false
      skia_use_freetype=true
      skia_use_system_freetype2=false
      skia_use_wuffs=true'

$SRC/depot_tools/gn gen out/Fuzz_mem_constraints\
    --args='cc="'$CC'"
      cxx="'$CXX'"
      is_debug=false
      extra_cflags_c=["'"$CFLAGS_ARR"'"]
      extra_cflags_cc=["'"$CXXFLAGS_ARR"'","-DIS_FUZZING"]
      extra_ldflags=["'"$LDFLAGS_ARR"'"]
      skia_enable_fontmgr_custom=false
      skia_enable_fontmgr_custom_empty=true
      skia_enable_gpu=true
      skia_enable_skottie=true
      skia_use_egl=true
      skia_use_fontconfig=false
      skia_use_freetype=true
      skia_use_system_freetype2=false
      skia_use_wuffs=true'

$SRC/depot_tools/ninja -C out/Fuzz region_deserialize region_set_path \
                                   path_deserialize image_decode \
                                   animated_image_decode api_draw_functions \
                                   api_gradients api_path_measure png_encoder \
                                   jpeg_encoder webp_encoder skottie_json \
                                   textblob_deserialize skjson \
                                   api_null_canvas api_image_filter api_pathop \
                                   api_polyutils android_codec image_decode_incremental \
                                   sksl2glsl sksl2spirv sksl2metal sksl2pipeline \
                                   api_skdescriptor skdescriptor_deserialize

$SRC/depot_tools/ninja -C out/Fuzz_mem_constraints image_filter_deserialize \
                                                   api_raster_n32_canvas \
                                                   api_mock_gpu_canvas

cp out/Fuzz/region_deserialize $OUT/region_deserialize
cp ./region_deserialize.options $OUT/region_deserialize.options

cp out/Fuzz/region_set_path $OUT/region_set_path
cp ./region_set_path.options $OUT/region_set_path.options
cp ./region_set_path_seed_corpus.zip $OUT/region_set_path_seed_corpus.zip

cp out/Fuzz/textblob_deserialize $OUT/textblob_deserialize
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

# Only create the width version of image_filter_deserialize if building with
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

cp out/Fuzz/api_path_measure $OUT/api_path_measure
cp ./api_path_measure.options $OUT/api_path_measure.options
cp ./api_path_measure_seed_corpus.zip $OUT/api_path_measure_seed_corpus.zip

cp out/Fuzz/api_pathop $OUT/api_pathop
cp ./api_pathop.options $OUT/api_pathop.options
cp ./api_pathop_seed_corpus.zip $OUT/api_pathop_seed_corpus.zip

cp out/Fuzz/png_encoder $OUT/png_encoder
cp ./encoder.options $OUT/png_encoder.options
cp ./encoder_seed_corpus.zip $OUT/png_encoder_seed_corpus.zip

cp out/Fuzz/jpeg_encoder $OUT/jpeg_encoder
cp ./encoder.options $OUT/jpeg_encoder.options
cp ./encoder_seed_corpus.zip $OUT/jpeg_encoder_seed_corpus.zip

cp out/Fuzz/webp_encoder $OUT/webp_encoder
cp ./encoder.options $OUT/webp_encoder.options
cp ./encoder_seed_corpus.zip $OUT/webp_encoder_seed_corpus.zip

cp out/Fuzz/skottie_json $OUT/skottie_json
cp ./skottie_json_seed_corpus.zip $OUT/skottie_json_seed_corpus.zip

cp out/Fuzz/skjson $OUT/skjson
cp json.dict $OUT/skjson.dict
cp ./skjson_seed_corpus.zip $OUT/skjson_seed_corpus.zip

cp out/Fuzz_mem_constraints/api_mock_gpu_canvas $OUT/api_mock_gpu_canvas
cp ./api_mock_gpu_canvas.options $OUT/api_mock_gpu_canvas.options
cp ./canvas_seed_corpus.zip $OUT/api_mock_gpu_canvas_seed_corpus.zip

cp out/Fuzz_mem_constraints/api_raster_n32_canvas $OUT/api_raster_n32_canvas
cp ./api_raster_n32_canvas.options $OUT/api_raster_n32_canvas.options
cp ./canvas_seed_corpus.zip $OUT/api_raster_n32_canvas_seed_corpus.zip

cp out/Fuzz/api_image_filter $OUT/api_image_filter
cp ./api_image_filter.options $OUT/api_image_filter.options
cp ./api_image_filter_seed_corpus.zip $OUT/api_image_filter_seed_corpus.zip

cp out/Fuzz/api_null_canvas $OUT/api_null_canvas
cp ./api_null_canvas.options $OUT/api_null_canvas.options
cp ./canvas_seed_corpus.zip $OUT/api_null_canvas_seed_corpus.zip

cp out/Fuzz/api_polyutils $OUT/api_polyutils
cp ./api_polyutils.options $OUT/api_polyutils.options
cp ./api_polyutils_seed_corpus.zip $OUT/api_polyutils_seed_corpus.zip

# These 2 can use the same corpus as the (non animated) image_decode.
cp out/Fuzz/android_codec $OUT/android_codec
cp ./android_codec.options $OUT/android_codec.options
cp ./image_decode_seed_corpus.zip $OUT/android_codec_seed_corpus.zip.

cp out/Fuzz/image_decode_incremental $OUT/image_decode_incremental
cp ./image_decode_incremental.options $OUT/image_decode_incremental.options
cp ./image_decode_seed_corpus.zip $OUT/image_decode_incremental_seed_corpus.zip

cp out/Fuzz/sksl2glsl $OUT/sksl2glsl
cp ./sksl2glsl.options $OUT/sksl2glsl.options
cp ./sksl_seed_corpus.zip $OUT/sksl2glsl_seed_corpus.zip

cp out/Fuzz/sksl2spirv $OUT/sksl2spirv
cp ./sksl2spirv.options $OUT/sksl2spirv.options
cp ./sksl_seed_corpus.zip $OUT/sksl2spirv_seed_corpus.zip

cp out/Fuzz/sksl2metal $OUT/sksl2metal
cp ./sksl2metal.options $OUT/sksl2metal.options
cp ./sksl_seed_corpus.zip $OUT/sksl2metal_seed_corpus.zip

cp out/Fuzz/sksl2pipeline $OUT/sksl2pipeline
cp ./sksl2pipeline.options $OUT/sksl2pipeline.options
cp ./sksl_seed_corpus.zip $OUT/sksl2pipeline_seed_corpus.zip

cp out/Fuzz/api_skdescriptor $OUT/api_skdescriptor
cp ./api_skdescriptor.options $OUT/api_skdescriptor.options
cp ./api_skdescriptor_seed_corpus.zip $OUT/api_skdescriptor_seed_corpus.zip

# Don't have any examples of an SkDescriptor atm, so some random bytes is all we have.
cp out/Fuzz/skdescriptor_deserialize $OUT/skdescriptor_deserialize
cp ./skdescriptor_deserialize.options $OUT/skdescriptor_deserialize.options
cp ./api_skdescriptor_seed_corpus.zip $OUT/skdescriptor_deserialize_seed_corpus.zip