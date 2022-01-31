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

# Mesa,libz/zlib, and xcb needed to build swiftshader
RUN apt-get update && apt-get install -y python wget libglu1-mesa-dev cmake lib32z1-dev zlib1g-dev libxext-dev libxcb-shm0-dev

RUN git clone 'https://chromium.googlesource.com/chromium/tools/depot_tools.git' --depth 1
ENV PATH="${SRC}/depot_tools:${PATH}"

RUN git clone https://skia.googlesource.com/skia.git --depth 1

# current directory for build script
WORKDIR skia

RUN bin/sync

# Make a directory for fuzzing artifacts that won't be clobbered by CIFuzz.
RUN mkdir $SRC/skia_data

RUN wget -O $SRC/skia_data/image_filter_deserialize_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/image_filter_deserialize_seed_corpus.zip

RUN wget -O $SRC/skia_data/region_set_path_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/region_set_path_seed_corpus.zip

RUN wget -O $SRC/skia_data/textblob_deserialize_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/textblob_deserialize_seed_corpus.zip

RUN wget -O $SRC/skia_data/path_deserialize_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/path_deserialize_seed_corpus.zip

RUN wget -O $SRC/skia_data/image_decode_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/image_decode_seed_corpus.zip

RUN wget -O $SRC/skia_data/animated_image_decode_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/animated_image_decode_seed_corpus.zip

RUN wget -O $SRC/skia_data/api_draw_functions_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/api_draw_functions_seed_corpus.zip

RUN wget -O $SRC/skia_data/api_gradients_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/api_gradients_seed_corpus.zip

RUN wget -O $SRC/skia_data/api_image_filter_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/api_image_filter_seed_corpus.zip

RUN wget -O $SRC/skia_data/api_path_measure_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/api_path_measure_seed_corpus.zip

RUN wget -O $SRC/skia_data/api_pathop_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/api_pathop_seed_corpus.zip

RUN wget -O $SRC/skia_data/canvas_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/canvas_seed_corpus.zip

RUN wget -O $SRC/skia_data/encoder_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/encoder_seed_corpus.zip

RUN wget -O $SRC/skia_data/skottie_json_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/skottie_json_seed_corpus.zip

RUN wget -O $SRC/skia_data/skjson_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/skjson_seed_corpus.zip

RUN wget -O $SRC/skia_data/api_polyutils_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/api_polyutils_seed_corpus.zip

RUN wget -O $SRC/skia_data/sksl_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/sksl_seed_corpus.zip

RUN wget -O $SRC/skia_data/svg_dom_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/svg_seed_corpus.zip

RUN wget -O $SRC/skia_data/sksl_with_256_padding_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/sksl_with_256_padding_seed_corpus.zip

RUN wget -O $SRC/skia_data/skp_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/skp_seed_corpus.zip

COPY image_filter_deserialize_width.options $SRC/skia_data/image_filter_deserialize_width.options

COPY json.dict $SRC/skia_data/json.dict

COPY sksl.dict $SRC/skia_data/sksl.dict

WORKDIR $SRC/skia

COPY build.sh $SRC/
