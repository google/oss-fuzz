# Copyright 2020 Google Inc.
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

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y -q && \
    apt-get install -y -q --no-install-recommends \
        bison \
        flex \
        ninja-build

ARG boost_version=1.89.0
# uuid and locale needed for Thrift source build
ARG boost_components=filesystem;system;process;multiprecision;crc;uuid;locale

RUN wget https://github.com/boostorg/boost/releases/download/boost-${boost_version}/boost-${boost_version}-cmake.tar.gz && \
    tar -xf boost-${boost_version}-cmake.tar.gz && \
    cd boost-${boost_version}/ && \
    mkdir -p build / && \
    cd build/ && \
    cmake .. -GNinja -DBOOST_INCLUDE_LIBRARIES="${boost_components}" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF && \
    cmake --build . --target install

RUN git clone --depth=1 --recurse-submodules \
    https://github.com/apache/arrow.git $SRC/arrow

COPY *.sh $SRC/
