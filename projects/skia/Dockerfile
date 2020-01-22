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

FROM gcr.io/oss-fuzz-base/base-builder
MAINTAINER kjlubick@chromium.org

# Mesa needed to build swiftshader
RUN apt-get update && apt-get install -y python wget libglu1-mesa-dev cmake

RUN git clone 'https://chromium.googlesource.com/chromium/tools/depot_tools.git' --depth 1
ENV PATH="${SRC}/depot_tools:${PATH}"

RUN git clone https://skia.googlesource.com/skia.git --depth 1

# current directory for build script
WORKDIR skia

RUN bin/sync

# Setup SwiftShader
WORKDIR $SRC/skia/third_party/externals/swiftshader/
# TODO(metzman): Come up with a better long term solution, such as downloading
# prebuilt libraries, than pinning swiftshader to a known working revision.
RUN git checkout bf8fd5b5fb6892dabcc21b4b86d41cd40cb9b4b5
RUN git submodule update --init
WORKDIR $SRC/skia

RUN wget -O $SRC/skia/image_filter_deserialize_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/image_filter_deserialize_seed_corpus.zip

RUN wget -O $SRC/skia/region_set_path_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/region_set_path_seed_corpus.zip

RUN wget -O $SRC/skia/textblob_deserialize_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/textblob_deserialize_seed_corpus.zip

RUN wget -O $SRC/skia/path_deserialize_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/path_deserialize_seed_corpus.zip

RUN wget -O $SRC/skia/image_decode_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/image_decode_seed_corpus.zip

RUN wget -O $SRC/skia/animated_image_decode_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/animated_image_decode_seed_corpus.zip

RUN wget -O $SRC/skia/api_draw_functions_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/api_draw_functions_seed_corpus.zip

RUN wget -O $SRC/skia/api_gradients_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/api_gradients_seed_corpus.zip

RUN wget -O $SRC/skia/api_image_filter_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/api_image_filter_seed_corpus.zip

RUN wget -O $SRC/skia/api_path_measure_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/api_path_measure_seed_corpus.zip

RUN wget -O $SRC/skia/api_pathop_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/api_pathop_seed_corpus.zip

RUN wget -O $SRC/skia/canvas_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/canvas_seed_corpus.zip

RUN wget -O $SRC/skia/encoder_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/encoder_seed_corpus.zip

RUN wget -O $SRC/skia/skottie_json_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/skottie_json_seed_corpus.zip

RUN wget -O $SRC/skia/skjson_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/skjson_seed_corpus.zip

RUN wget -O $SRC/skia/api_polyutils_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/api_polyutils_seed_corpus.zip

RUN wget -O $SRC/skia/sksl_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/sksl_seed_corpus.zip

RUN wget -O $SRC/skia/api_skdescriptor_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/api_skdescriptor_seed_corpus.zip

COPY build.sh $SRC/

COPY skia.diff $SRC/skia/skia.diff
RUN git apply skia.diff

COPY region_deserialize.options $SRC/skia/region_deserialize.options
COPY region_set_path.options $SRC/skia/region_set_path.options
COPY image_filter_deserialize.options $SRC/skia/image_filter_deserialize.options
COPY image_filter_deserialize_width.options $SRC/skia/image_filter_deserialize_width.options
COPY textblob_deserialize.options $SRC/skia/textblob_deserialize.options
COPY path_deserialize.options $SRC/skia/path_deserialize.options
COPY encoder.options $SRC/skia/encoder.options
COPY skdescriptor_deserialize.options $SRC/skia/skdescriptor_deserialize.options

# Codec fuzzers can share options
COPY image_codec.options $SRC/skia/android_codec.options
COPY image_codec.options $SRC/skia/animated_image_decode.options
COPY image_codec.options $SRC/skia/image_decode.options
COPY image_codec.options $SRC/skia/image_decode_incremental.options

# API fuzzers can share options
COPY api_fuzzers.options $SRC/skia/api_draw_functions.options
COPY api_fuzzers.options $SRC/skia/api_gradients.options
COPY api_fuzzers.options $SRC/skia/api_image_filter.options
COPY api_fuzzers.options $SRC/skia/api_mock_gpu_canvas.options
COPY api_fuzzers.options $SRC/skia/api_null_canvas.options
COPY api_fuzzers.options $SRC/skia/api_path_measure.options
COPY api_fuzzers.options $SRC/skia/api_pathop.options
COPY api_fuzzers.options $SRC/skia/api_polyutils.options
COPY api_fuzzers.options $SRC/skia/api_raster_n32_canvas.options
COPY api_fuzzers.options $SRC/skia/api_skdescriptor.options

# SKSL fuzzers can share options
COPY sksl.options $SRC/skia/sksl2glsl.options
COPY sksl.options $SRC/skia/sksl2spirv.options
COPY sksl.options $SRC/skia/sksl2metal.options
COPY sksl.options $SRC/skia/sksl2pipeline.options

COPY json.dict $SRC/skia/json.dict

COPY BUILD.gn.diff $SRC/skia/BUILD.gn.diff
RUN cat BUILD.gn.diff >> BUILD.gn
