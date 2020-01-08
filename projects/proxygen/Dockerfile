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
MAINTAINER mhl@fb.com

# Install packages we need to build dependencies
RUN apt-get update && \
    apt-get install -y \
    make \
    autoconf \
    automake \
    libtool \
    sudo \
    wget \
    gcc \
    g++ \
    python \
    python-dev

# We need a newer version of CMake than is available in the base builder image
RUN wget https://github.com/Kitware/CMake/releases/download/v3.15.2/cmake-3.15.2.tar.gz && \
    tar xzf cmake-3.15.2.tar.gz && \
    cd cmake-3.15.2 && \
    export CC=clang && \
    export CXX=clang++ && \
    CXXFLAGS="" && \
    CFLAGS="" && \
    ./bootstrap && \
    make -j$(nproc) && \
    make install && \
    cd .. && \
    rm -rf cmake-3.15.2

# Install and build boost from source so we can have it use libc++
RUN wget https://dl.bintray.com/boostorg/release/1.70.0/source/boost_1_70_0.tar.gz && \
    tar xzf boost_1_70_0.tar.gz && \
    cd boost_1_70_0 && \
    ./bootstrap.sh --with-toolset=clang && \
    ./b2 clean && \
    ./b2 toolset=clang cxxflags="-stdlib=libc++" linkflags="-stdlib=libc++" -j$(nproc) install && \
    cd .. && \
    rm -rf boost_1_70_0

# Build gflags/glog/gtest from source so we use libc++ and avoid incompatibilities with the std::string ABI breaking changes
RUN sudo apt-get purge libgflags-dev

RUN wget https://github.com/gflags/gflags/archive/v2.2.2.tar.gz && \
    tar xzf v2.2.2.tar.gz && \
    cd gflags-2.2.2 && \
    mkdir build && \
    cd build && \
    export CC=clang && \
    export CXX=clang++ && \
    export CXXFLAGS="-stdlib=libc++" && \
    cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON .. && \
    make -j$(nproc) && \
    sudo make install && \
    cd ../../ && \
    rm -rf gflags-2.2.2

RUN wget https://github.com/google/glog/archive/v0.4.0.tar.gz && \
    tar xzf v0.4.0.tar.gz && \
    cd glog-0.4.0 && \
    export CC=clang && \
    export CXX=clang++ && \
    export CXXFLAGS="-stdlib=libc++" && \
    mkdir build && \
    cd build && \
    cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_VERBOSE_MAKEFILE=ON .. && \
    make -j$(nproc) && \
    sudo make install && \
    cd ../.. && \
    rm -rf glog-0.4.0

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

# Build and install zstd from source so we have it available for proxygen
RUN wget https://github.com/facebook/zstd/releases/download/v1.4.2/zstd-1.4.2.tar.gz && \
    tar xzf zstd-1.4.2.tar.gz && \
    cd zstd-1.4.2 && \
    export CC=clang && \
    export CXX=clang++ && \
    export CXXFLAGS="-stdlib=libc++" && \
    sudo make -j$(nproc) install && \
    cd .. && \
    rm -rf zstd-1.4.2

# Build and install `fmt` needed by folly
RUN wget https://github.com/fmtlib/fmt/archive/6.0.0.tar.gz && \
    tar xzf 6.0.0.tar.gz && \
    cd fmt-6.0.0 && \
    export CC=clang && \
    export CXX=clang++ && \
    export CXXFLAGS="-stdlib=libc++" && \
    mkdir build && \
    cd build && \
    cmake .. && \
    make -j$(nproc) && \
    sudo make install && \
    cd ../.. && \
    rm -rf fmt-6.0.0

# Replicate `install-dependencies` from the proxygen `build.sh` script
RUN apt-get install -y \
    git \
    flex \
    bison \
    libkrb5-dev \
    libsasl2-dev \
    libnuma-dev \
    pkg-config \
    libssl-dev \
    libcap-dev \
    gperf \
    libevent-dev \
    libtool \
    libjemalloc-dev \
    unzip \
    libiberty-dev \
    liblzma-dev \
    zlib1g-dev \
    binutils-dev \
    libsodium-dev \
    libdouble-conversion-dev \
    libunwind8-dev

# Install patchelf so we can fix path to libunwind
RUN apt-get install patchelf

# Fetch source and copy over files
RUN git clone --depth 1 https://github.com/facebook/proxygen.git proxygen
WORKDIR proxygen
COPY build.sh $SRC/