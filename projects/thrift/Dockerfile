# Copyright 2021 Google LLC
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

# We use compile_go_fuzzer in this set up and also go itself
FROM gcr.io/oss-fuzz-base/base-builder-go

RUN apt-get update && apt-get install -y libssl-dev pkg-config autoconf automake libtool bison flex wget make \
    autoconf \
    automake \
    sudo \
    gcc \
    g++ \
    python-dev \
    cmake \
    ninja-build

RUN wget https://github.com/boostorg/boost/releases/download/boost-1.87.0/boost-1.87.0-cmake.tar.gz && \
    tar -xvf boost-1.87.0-cmake.tar.gz && \
    cd boost-1.87.0/ && \
    CFLAGS="" CXXFLAGS="" ./bootstrap.sh && \
    CFLAGS="" CXXFLAGS="" ./b2 headers && \
    CFLAGS="" CXXFLAGS="" ./b2 runtime-link=static link=static variant=release install -j 10 && \
    cp -R -f boost/ /usr/include/

#libboost-all-dev
RUN git clone --depth 1 https://github.com/apache/thrift
WORKDIR $SRC/thrift
COPY build.sh $SRC/
