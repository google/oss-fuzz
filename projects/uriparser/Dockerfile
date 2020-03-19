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
MAINTAINER sebastian@pipping.org
RUN apt-get update && apt-get install -y make autoconf automake wget sudo libtool cmake libgtest-dev
RUN wget https://github.com/google/googletest/archive/release-1.8.1.tar.gz && \
    tar xzf release-1.8.1.tar.gz && \
    cd googletest-release-1.8.1 && \
    export CC=clang && \
    export CXX=clang++ && \
    export CXXFLAGS="-stdlib=libc++" && \
    mkdir build && \
    cd build && \
    cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_VERBOSE_MAKEFILE=ON .. && \
    make -j$(nproc) && \
    sudo make install && \
    cd ../.. && \
    rm -rf googletest-release-1.8.1
RUN git clone --depth 1 https://github.com/uriparser/uriparser uriparser
WORKDIR uriparser
COPY build.sh *.cc $SRC/
