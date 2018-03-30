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

RUN apt-get update && apt-get install -y python wget libglu1-mesa-dev patchelf

RUN git clone 'https://chromium.googlesource.com/chromium/tools/depot_tools.git'
ENV PATH="${SRC}/depot_tools:${PATH}"

# checkout all sources needed to build your project
RUN git clone https://skia.googlesource.com/skia.git

# current directory for build script
WORKDIR skia

RUN python tools/git-sync-deps

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

RUN wget -O $SRC/skia/canvas_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/canvas_seed_corpus.zip

RUN wget -O $SRC/skia/encoder_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/encoder_seed_corpus.zip

COPY build.sh $SRC/

COPY skia.diff $SRC/skia/skia.diff
RUN git apply skia.diff

COPY region_deserialize.options $SRC/skia/region_deserialize.options
COPY region_set_path.options $SRC/skia/region_set_path.options
COPY image_filter_deserialize.options $SRC/skia/image_filter_deserialize.options
COPY image_filter_deserialize_width.options $SRC/skia/image_filter_deserialize_width.options
COPY textblob_deserialize.options $SRC/skia/textblob_deserialize.options
COPY path_deserialize.options $SRC/skia/path_deserialize.options
COPY image_decode.options $SRC/skia/image_decode.options
COPY animated_image_decode.options $SRC/skia/animated_image_decode.options
COPY encoder.options $SRC/skia/encoder.options

# API fuzzers can share options
COPY api_fuzzers.options $SRC/skia/api_draw_functions.options
COPY api_fuzzers.options $SRC/skia/api_gradients.options
COPY api_fuzzers.options $SRC/skia/api_image_filter.options
COPY api_fuzzers.options $SRC/skia/api_path_measure.options
COPY api_fuzzers.options $SRC/skia/api_raster_n32_canvas.options
COPY api_fuzzers.options $SRC/skia/api_null_canvas.options

COPY BUILD.gn.diff $SRC/skia/BUILD.gn.diff
RUN cat BUILD.gn.diff >> BUILD.gn
