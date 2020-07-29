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
RUN git checkout 45510ad8a77862c1ce2e33f0efed41544f5f048b
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

RUN wget -O $SRC/skia/svg_dom_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/svg_seed_corpus.zip 

RUN wget -O $SRC/skia/sksl_with_256_padding_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/sksl_with_256_padding_seed_corpus.zip

COPY build.sh $SRC/

COPY skia.diff $SRC/skia/skia.diff
RUN git apply skia.diff

COPY image_filter_deserialize_width.options $SRC/skia/image_filter_deserialize_width.options

COPY json.dict $SRC/skia/json.dict

COPY BUILD.gn.diff $SRC/skia/BUILD.gn.diff
RUN cat BUILD.gn.diff >> BUILD.gn
