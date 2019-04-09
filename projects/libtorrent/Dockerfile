# Copyright 2019 Google Inc.
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
MAINTAINER oss-fuzz-libtorrent@pauldreik.se
RUN echo "CXX=$CXX"
RUN echo "CXXFLAGS=$CXXFLAGS"
RUN apt-get update && apt-get install -y make ninja-build wget libssl-dev libgeoip-dev pkg-config

RUN wget --no-verbose https://dl.bintray.com/boostorg/release/1.69.0/source/boost_1_69_0.tar.gz
RUN tar xvzf boost_1_69_0.tar.gz
RUN cd boost_1_69_0 && ./bootstrap.sh --with-toolset=clang --prefix=/usr --with-libraries=system && ./b2 clean && ./b2 toolset=clang cxxflags="$CXXFLAGS" install

RUN wget --no-verbose https://github.com/Kitware/CMake/releases/download/v3.14.0/cmake-3.14.0-Linux-x86_64.sh
RUN sh cmake-3.14.0-Linux-x86_64.sh --prefix=/usr/local --exclude-subdir

RUN git clone --single-branch --branch ossfuzz https://github.com/pauldreik/libtorrent.git

WORKDIR libtorrent
COPY build.sh $SRC/

