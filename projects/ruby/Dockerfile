# Copyright 2025 Google LLC
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
RUN apt-get update && apt-get install -y \
    libssl-dev \
    libyaml-dev \
    zlib1g-dev \
    ruby \
    ruby-dev \
    autoconf \
    automake \
    libtool \
    bison \
    wget
RUN git clone --depth=1 --single-branch https://github.com/ruby/ruby $SRC/ruby
COPY build.sh $SRC/build.sh
COPY fuzz_regex.cpp $SRC/fuzz_regex.cpp
COPY fuzz_string.cpp $SRC/fuzz_string.cpp
COPY fuzz_hash.cpp $SRC/fuzz_hash.cpp
COPY fuzz_bignum.cpp $SRC/fuzz_bignum.cpp
COPY fuzz_array.cpp $SRC/fuzz_array.cpp
COPY fuzz_iseq.cpp $SRC/fuzz_iseq.cpp
COPY fuzz_pack.cpp $SRC/fuzz_pack.cpp
COPY fuzz_json.c $SRC/fuzz_json.c
COPY fuzz_prism.cpp $SRC/fuzz_prism.cpp
COPY fuzz_prism.options $SRC/fuzz_prism.options
COPY fuzz_ruby_parser.cpp $SRC/fuzz_ruby_parser.cpp
WORKDIR $SRC
