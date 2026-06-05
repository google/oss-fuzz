# Copyright 2024 Google LLC
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

# Build tools and MapBuffer runtime dependency (glog/gflags).
# libgflags-dev is pulled in transitively by libgoogle-glog-dev on some
# Ubuntu versions but listed explicitly for reproducibility.
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    ninja-build \
    libgoogle-glog-dev \
    libgflags-dev

# fast_float – header-only, IEEE 754 float parser required by CSSTokenizer.
RUN git clone --depth 1 https://github.com/fastfloat/fast_float.git fast_float

# React Native monorepo (shallow clone – we only need ReactCommon C++ sources).
RUN git clone --depth 1 https://github.com/facebook/react-native.git react-native

WORKDIR $SRC/react-native

COPY build.sh \
     fuzz_mapbuffer.cpp \
     fuzz_css_tokenizer.cpp \
     fuzz_css_value_parser.cpp \
     $SRC/
