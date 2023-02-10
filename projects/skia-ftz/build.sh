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

# Build SwiftShader so we can compile in our GPU code and test it in an
# an environment that does not have a real GPU.
pushd third_party/externals/swiftshader/
export SWIFTSHADER_INCLUDE_PATH=$PWD/include
# SwiftShader already has a build/ directory, use something else
rm -rf build_swiftshader
mkdir build_swiftshader

cd build_swiftshader
if [ $SANITIZER == "address" ]; then
  CMAKE_SANITIZER="SWIFTSHADER_ASAN"
elif [ $SANITIZER == "memory" ]; then
  CMAKE_SANITIZER="SWIFTSHADER_MSAN"
  # oss-fuzz will patch the rpath for this after compilation and linking,
  # so we only need to set this to appease the Swiftshader build rules check.
  export SWIFTSHADER_MSAN_INSTRUMENTED_LIBCXX_PATH="/does/not/matter"
elif [ $SANITIZER == "undefined" ]; then
  # The current SwiftShader build needs -fno-sanitize=vptr, but it cannot be
  # specified here since -fsanitize=undefined will always come after any
  # user specified flags passed to cmake. SwiftShader does not need to be
  # built with the undefined sanitizer in order to fuzz Skia, so don't.
  CMAKE_SANITIZER="SWIFTSHADER_UBSAN_DISABLED"
elif [ $SANITIZER == "coverage" ]; then
  CMAKE_SANITIZER="SWIFTSHADER_EMIT_COVERAGE"
elif [ $SANITIZER == "thread" ]; then
  CMAKE_SANITIZER="SWIFTSHADER_UBSAN_DISABLED"
else
  exit 1
fi
# These deprecated warnings get quite noisy and mask other issues.
CFLAGS= CXXFLAGS="-stdlib=libc++ -Wno-deprecated-declarations" cmake .. -GNinja \
  -DCMAKE_MAKE_PROGRAM="$SRC/depot_tools/ninja" -D$CMAKE_SANITIZER=1 -DSWIFTSHADER_WARNINGS_AS_ERRORS=FALSE

# Swiftshader only supports Vulkan, so we will build our fuzzers with Vulkan too.
$SRC/depot_tools/ninja libvk_swiftshader.so
mv libvk_swiftshader.so $OUT
export SWIFTSHADER_LIB_PATH=$OUT

popd
# These are any clang warnings we need to silence.
DISABLE="-Wno-zero-as-null-pointer-constant -Wno-unused-template
         -Wno-cast-qual"
# Disable UBSan vptr since target built with -fno-rtti.
export CFLAGS="$CFLAGS $DISABLE -I$SWIFTSHADER_INCLUDE_PATH \
 -DSK_GPU_TOOLS_VK_LIBRARY_NAME=libvk_swiftshader.so \
 -fno-sanitize=vptr -DSK_BUILD_FOR_LIBFUZZER"
export CXXFLAGS="$CXXFLAGS $DISABLE -I$SWIFTSHADER_INCLUDE_PATH \
 -fno-sanitize=vptr -DSK_BUILD_FOR_LIBFUZZER"
export LDFLAGS="$LIB_FUZZING_ENGINE -l :crtfastmath.o $CXXFLAGS -L$SWIFTSHADER_LIB_PATH"

# This splits a space separated list into a quoted, comma separated list for gn.
export CFLAGS_ARR=`echo $CFLAGS | sed -e "s/\s/\",\"/g"`
export CXXFLAGS_ARR=`echo $CXXFLAGS | sed -e "s/\s/\",\"/g"`
export LDFLAGS_ARR=`echo $LDFLAGS | sed -e "s/\s/\",\"/g"`

$SRC/skia/bin/fetch-gn

# Avoid OOMs on the CI due to lower memory constraints
LIMITED_LINK_POOL="link_pool_depth=1"

SKIA_ARGS="skia_build_fuzzers=true
           skia_enable_fontmgr_custom_directory=false
           skia_enable_fontmgr_custom_embedded=false
           skia_enable_fontmgr_custom_empty=true
           skia_enable_gpu=true
           skia_enable_skottie=true
           skia_use_vulkan=true
           skia_use_egl=false
           skia_use_gl=false
           skia_use_fontconfig=false
           skia_use_freetype=true
           skia_use_system_freetype2=false
           skia_use_wuffs=true
           skia_use_libfuzzer_defaults=false"

# Even though GPU is "enabled" for all these builds, none really
# uses the gpu except for api_mock_gpu_canvas.
$SRC/skia/bin/gn gen out/Fuzz\
    --args='cc="'$CC'"
      cxx="'$CXX'"
      '"$LIMITED_LINK_POOL"'
      '"${SKIA_ARGS[*]}"'
      is_debug=false
      extra_cflags_c=["'"$CFLAGS_ARR"'"]
      extra_cflags_cc=["'"$CXXFLAGS_ARR"'"]
      extra_ldflags=["'"$LDFLAGS_ARR"'"]'

# Some fuzz targets benefit from assertions so we enable SK_DEBUG to allow SkASSERT
# and SkDEBUGCODE to run. We still enable optimization (via is_debug=false) because
# faster code means more fuzz tests and deeper coverage.
$SRC/skia/bin/gn gen out/FuzzDebug\
    --args='cc="'$CC'"
      cxx="'$CXX'"
      '"$LIMITED_LINK_POOL"'
      '"${SKIA_ARGS[*]}"'
      is_debug=false
      extra_cflags_c=["-DSK_DEBUG","'"$CFLAGS_ARR"'"]
      extra_cflags_cc=["-DSK_DEBUG","'"$CXXFLAGS_ARR"'"]
      extra_ldflags=["'"$LDFLAGS_ARR"'"]'

$SRC/depot_tools/ninja -C out/Fuzz \
  android_codec \
  animated_image_decode \
  api_create_ddl \
  api_ddl_threading \
  api_draw_functions \
  api_gradients \
  api_image_filter \
  api_mock_gpu_canvas \
  api_null_canvas \
  api_path_measure \
  api_pathop \
  api_polyutils \
  api_raster_n32_canvas \
  api_regionop \
  api_skparagraph \
  api_svg_canvas \
  api_triangulation \
  colrv1 \
  image_decode \
  image_decode_incremental \
  image_filter_deserialize \
  jpeg_encoder \
  path_deserialize \
  png_encoder \
  region_deserialize \
  region_set_path \
  skdescriptor_deserialize \
  skjson \
  skottie_json \
  skp \
  svg_dom \
  textblob_deserialize \
  webp_encoder

$SRC/depot_tools/ninja -C out/FuzzDebug \
  skruntimeeffect \
  sksl2glsl \
  sksl2metal \
  sksl2pipeline \
  sksl2spirv \

rm -rf $OUT/data
mkdir $OUT/data

mv out/Fuzz/region_deserialize $OUT/region_deserialize

mv out/Fuzz/region_set_path $OUT/region_set_path
mv ../skia_data/region_set_path_seed_corpus.zip $OUT/region_set_path_seed_corpus.zip

mv out/Fuzz/textblob_deserialize $OUT/textblob_deserialize
mv ../skia_data/textblob_deserialize_seed_corpus.zip $OUT/textblob_deserialize_seed_corpus.zip

mv out/Fuzz/path_deserialize $OUT/path_deserialize
mv ../skia_data/path_deserialize_seed_corpus.zip $OUT/path_deserialize_seed_corpus.zip

mv out/Fuzz/animated_image_decode $OUT/animated_image_decode
mv ../skia_data/animated_image_decode_seed_corpus.zip $OUT/animated_image_decode_seed_corpus.zip

# Only create the width version of image_filter_deserialize if building with
# libfuzzer, since it depends on a libfuzzer specific flag.
if [ "$FUZZING_ENGINE" == "libfuzzer" ]
then
  # Use the same binary as image_filter_deserialize.
  cp out/Fuzz/image_filter_deserialize $OUT/image_filter_deserialize_width
  mv ../skia_data/image_filter_deserialize_width.options $OUT/image_filter_deserialize_width.options
  # Use the same seed corpus as image_filter_deserialize.
  cp ../skia_data/image_filter_deserialize_seed_corpus.zip $OUT/image_filter_deserialize_width_seed_corpus.zip
fi

mv out/Fuzz/image_filter_deserialize $OUT/image_filter_deserialize
mv ../skia_data/image_filter_deserialize_seed_corpus.zip $OUT/image_filter_deserialize_seed_corpus.zip

mv out/Fuzz/api_draw_functions $OUT/api_draw_functions
mv ../skia_data/api_draw_functions_seed_corpus.zip $OUT/api_draw_functions_seed_corpus.zip

mv out/Fuzz/api_gradients $OUT/api_gradients
mv ../skia_data/api_gradients_seed_corpus.zip $OUT/api_gradients_seed_corpus.zip

mv out/Fuzz/api_path_measure $OUT/api_path_measure
mv ../skia_data/api_path_measure_seed_corpus.zip $OUT/api_path_measure_seed_corpus.zip

mv out/Fuzz/api_pathop $OUT/api_pathop
mv ../skia_data/api_pathop_seed_corpus.zip $OUT/api_pathop_seed_corpus.zip

# These 3 use the same corpus.
mv out/Fuzz/png_encoder $OUT/png_encoder
cp ../skia_data/encoder_seed_corpus.zip $OUT/png_encoder_seed_corpus.zip

mv out/Fuzz/jpeg_encoder $OUT/jpeg_encoder
cp ../skia_data/encoder_seed_corpus.zip $OUT/jpeg_encoder_seed_corpus.zip

mv out/Fuzz/webp_encoder $OUT/webp_encoder
mv ../skia_data/encoder_seed_corpus.zip $OUT/webp_encoder_seed_corpus.zip

mv out/Fuzz/skottie_json $OUT/skottie_json
mv ../skia_data/skottie_json_seed_corpus.zip $OUT/skottie_json_seed_corpus.zip

mv out/Fuzz/skjson $OUT/skjson
mv ../skia_data/json.dict $OUT/skjson.dict
mv ../skia_data/skjson_seed_corpus.zip $OUT/skjson_seed_corpus.zip

# These 4 use the same canvas_seed_corpus.
mv out/Fuzz/api_mock_gpu_canvas $OUT/api_mock_gpu_canvas
cp ../skia_data/canvas_seed_corpus.zip $OUT/api_mock_gpu_canvas_seed_corpus.zip

mv out/Fuzz/api_raster_n32_canvas $OUT/api_raster_n32_canvas
cp ../skia_data/canvas_seed_corpus.zip $OUT/api_raster_n32_canvas_seed_corpus.zip

mv out/Fuzz/api_svg_canvas $OUT/api_svg_canvas
cp ../skia_data/canvas_seed_corpus.zip $OUT/api_svg_canvas_seed_corpus.zip

mv out/Fuzz/api_null_canvas $OUT/api_null_canvas
mv ../skia_data/canvas_seed_corpus.zip $OUT/api_null_canvas_seed_corpus.zip

mv out/Fuzz/api_image_filter $OUT/api_image_filter
mv ../skia_data/api_image_filter_seed_corpus.zip $OUT/api_image_filter_seed_corpus.zip

mv out/Fuzz/api_polyutils $OUT/api_polyutils
mv ../skia_data/api_polyutils_seed_corpus.zip $OUT/api_polyutils_seed_corpus.zip

# These 3 use the same corpus.
mv out/Fuzz/image_decode $OUT/image_decode
cp ../skia_data/image_decode_seed_corpus.zip $OUT/image_decode_seed_corpus.zip

mv out/Fuzz/android_codec $OUT/android_codec
cp ../skia_data/image_decode_seed_corpus.zip $OUT/android_codec_seed_corpus.zip.

mv out/Fuzz/image_decode_incremental $OUT/image_decode_incremental
mv ../skia_data/image_decode_seed_corpus.zip $OUT/image_decode_incremental_seed_corpus.zip

# All five SkSL tests share the same sksl_seed_corpus and dictionary.
mv out/FuzzDebug/sksl2glsl $OUT/sksl2glsl
cp ../skia_data/sksl.dict $OUT/sksl2glsl.dict
cp ../skia_data/sksl_seed_corpus.zip $OUT/sksl2glsl_seed_corpus.zip

mv out/FuzzDebug/sksl2spirv $OUT/sksl2spirv
cp ../skia_data/sksl.dict $OUT/sksl2spirv.dict
cp ../skia_data/sksl_seed_corpus.zip $OUT/sksl2spirv_seed_corpus.zip

mv out/FuzzDebug/sksl2metal $OUT/sksl2metal
cp ../skia_data/sksl.dict $OUT/sksl2metal.dict
cp ../skia_data/sksl_seed_corpus.zip $OUT/sksl2metal_seed_corpus.zip

mv out/FuzzDebug/sksl2pipeline $OUT/sksl2pipeline
cp ../skia_data/sksl.dict $OUT/sksl2pipeline.dict
cp ../skia_data/sksl_seed_corpus.zip $OUT/sksl2pipeline_seed_corpus.zip

mv out/FuzzDebug/skruntimeeffect $OUT/skruntimeeffect
mv ../skia_data/sksl.dict $OUT/skruntimeeffect.dict
mv ../skia_data/sksl_seed_corpus.zip $OUT/skruntimeeffect_seed_corpus.zip

mv out/Fuzz/skdescriptor_deserialize $OUT/skdescriptor_deserialize
mv ../skia_data/skdescriptor_deserialize_seed_corpus.zip $OUT/skdescriptor_deserialize_seed_corpus.zip

mv out/Fuzz/svg_dom $OUT/svg_dom
mv ../skia_data/svg_dom_seed_corpus.zip $OUT/svg_dom_seed_corpus.zip

mv out/Fuzz/api_create_ddl $OUT/api_create_ddl

mv out/Fuzz/api_ddl_threading $OUT/api_ddl_threading

mv out/Fuzz/skp $OUT/skp
mv ../skia_data/skp_seed_corpus.zip $OUT/skp_seed_corpus.zip

mv out/Fuzz/api_skparagraph $OUT/api_skparagraph

mv out/Fuzz/api_regionop $OUT/api_regionop

mv out/Fuzz/api_triangulation $OUT/api_triangulation

mv out/Fuzz/colrv1 $OUT/colrv1
mv ../skia_data/colrv1_seed_corpus.zip $OUT/colrv1_seed_corpus.zip
