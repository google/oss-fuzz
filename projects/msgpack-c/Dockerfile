# Copyright 2018 Google Inc.
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
RUN apt-get update && apt-get install -y cmake wget bzip2
RUN git clone --depth 1 --single-branch --branch cpp_master https://github.com/msgpack/msgpack-c.git msgpack-c

RUN wget https://boostorg.jfrog.io/artifactory/main/release/1.70.0/source/boost_1_70_0.tar.bz2 && \
    tar xf boost_1_70_0.tar.bz2 && \
    cd boost_1_70_0 && \
    ./bootstrap.sh --with-toolset=clang --prefix=/usr && \
    ./b2 -j$(nproc) toolset=clang --with-chrono --with-context --with-filesystem --with-system --with-timer address-model=64 cflags="$CFLAGS" cxxflags="$CXXFLAGS"  link=static variant=release runtime-link=static threading=multi install

WORKDIR msgpack-c
COPY build.sh $SRC/
