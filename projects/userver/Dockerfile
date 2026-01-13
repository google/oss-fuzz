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
RUN apt-get update && apt-get install -y make autoconf automake libtool ninja-build libyaml-cpp-dev libzstd-dev libre2-dev libicu-dev zlib1g-dev libnghttp2-dev libev-dev clang-format
RUN apt-get update && apt-get install -y ccache cmake git libbenchmark-dev libbson-dev libcctz-dev libcurl4-openssl-dev libev-dev libgmock-dev libc-ares-dev libfmt-dev libgrpc-dev libgrpc++-dev libgrpc++1 libgtest-dev libhiredis-dev libjemalloc-dev libkrb5-dev libldap2-dev libmongoc-dev libnghttp2-dev libpq-dev libprotoc-dev libssl-dev libyaml-cpp-dev ninja-build pkg-config protobuf-compiler-grpc python3-dev python3-jinja2 python3-pip python3-protobuf python3-venv python3-voluptuous zlib1g-dev chrpath libstdc++-10-dev

#Ubuntu 20.04 contains only boost 1.74.0
RUN wget https://archives.boost.io/release/1.81.0/source/boost_1_81_0.tar.gz && \
    tar xzf boost_1_81_0.tar.gz && \
    cd boost_1_81_0 && \
    CXXFLAGS="" LDFLAGS="" ./bootstrap.sh --with-toolset=clang && \
    ./b2 -j$(nproc) link=static install
RUN git clone --depth 1 https://github.com/userver-framework/userver userver

RUN python3 userver/scripts/userver-create-service.py fuzzservice

RUN apt remove -y clang-format
RUN apt-get update && apt install -y clang-format-18
RUN ln -s /usr/bin/clang-format-18 /usr/bin/clang-format

COPY build.sh $SRC/
COPY main.cpp $SRC/
COPY CMakeLists.txt $SRC/
COPY CMakePresets.json $SRC/fuzzservice/
COPY static_config.yaml $SRC/fuzzservice/
