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
MAINTAINER greg.landrum@gmail.com
RUN apt-get update && apt-get install -y make wget cmake \
  libeigen3-dev python3 libpython3-all-dev \
  zlib1g-dev \
  libbz2-dev

# Install latest cmake
RUN wget --quiet https://github.com/Kitware/CMake/releases/download/v3.14.5/cmake-3.14.5-Linux-x86_64.sh; \
    chmod +x cmake-3.14.5-Linux-x86_64.sh; \
    ./cmake-3.14.5-Linux-x86_64.sh --skip-license --prefix="/usr/local"

# We're building `rdkit` using clang, but the boost package is built using gcc.
# For whatever reason, linking would fail.
# (Mismatch between libstdc++ and libc++ maybe?)
# It works if we build `rdkit` using gcc or build boost using clang instead.
# We've opted for building boost using clang.
RUN cd $SRC && \
    wget --quiet https://sourceforge.net/projects/boost/files/boost/1.69.0/boost_1_69_0.tar.bz2 && \
    tar xjf boost_1_69_0.tar.bz2 && \
    cd $SRC/boost_1_69_0 && \
    ./bootstrap.sh --with-toolset=clang --with-libraries=serialization,system,iostreams,regex && \
    ./b2 -q -j2 toolset=clang cxxflags="-fPIC $CXXFLAGS $CXXFLAGS_EXTRA" link=static install

RUN git clone --depth 1 https://github.com/rdkit/rdkit.git $SRC/rdkit
WORKDIR $SRC/rdkit
COPY build.sh $SRC/
