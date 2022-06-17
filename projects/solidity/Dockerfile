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
RUN apt-get update && apt-get install -y make autoconf automake libtool \
    build-essential libbz2-dev ninja-build zlib1g-dev wget python python-dev \
    liblzma-dev uuid-dev pkg-config openjdk-8-jdk unzip mlton

RUN git clone --recursive -b develop https://github.com/ethereum/solidity.git solidity
RUN git clone --depth 1 https://github.com/ethereum/solidity-fuzzing-corpus.git
RUN git clone --depth 1 -b add-newline https://github.com/bshastry/libprotobuf-mutator.git
# evmone v0.8.2 fixes: https://github.com/ethereum/evmone/issues/373
RUN git clone --branch="v0.8.2" --recurse-submodules \
    https://github.com/ethereum/evmone.git

# Install statically built dependencies in "/usr" directory
# Install boost
RUN cd $SRC; \
    wget -q 'https://boostorg.jfrog.io/artifactory/main/release/1.73.0/source/boost_1_73_0.tar.bz2' -O boost.tar.bz2; \
    test "$(sha256sum boost.tar.bz2)" = "4eb3b8d442b426dc35346235c8733b5ae35ba431690e38c6a8263dce9fcbb402  boost.tar.bz2"; \
    tar -xf boost.tar.bz2; \
    rm boost.tar.bz2; \
    cd boost_1_73_0; \
    CXXFLAGS="-stdlib=libc++ -pthread" LDFLAGS="-stdlib=libc++" ./bootstrap.sh --with-toolset=clang --prefix=/usr; \
    ./b2 toolset=clang cxxflags="-stdlib=libc++ -pthread" linkflags="-stdlib=libc++ -pthread" headers; \
    ./b2 toolset=clang cxxflags="-stdlib=libc++ -pthread" linkflags="-stdlib=libc++ -pthread" \
        link=static variant=release runtime-link=static \
        system filesystem unit_test_framework program_options \
        install -j $(($(nproc)/2)); \
    rm -rf $SRC/boost_1_73_0

# Install libprotobuf-mutator
RUN mkdir $SRC/LPM; \
    cd $SRC/LPM; \
    cmake $SRC/libprotobuf-mutator -GNinja \
    -DLIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF=ON -DLIB_PROTO_MUTATOR_TESTING=OFF \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="/usr"; \
    ninja; \
    ninja install; \
    cd external.protobuf; \
    cp -Rf bin lib include /usr;

# Install evmone
RUN cd $SRC/evmone; \
    mkdir -p build; \
    cd build; \
    cmake .. -G Ninja -DBUILD_SHARED_LIBS=OFF -DCMAKE_INSTALL_PREFIX="/usr"; \
    ninja; \
    ninja install;

# gmp
RUN cd $SRC; \
    # Replace system installed libgmp static library
    # with sanitized version
    rm -f /usr/lib/x86_64-linux-gnu/libgmp.a; \
    wget -q 'https://gmplib.org/download/gmp/gmp-6.2.1.tar.xz' -O gmp.tar.xz; \
    test "$(sha256sum gmp.tar.xz)" = "fd4829912cddd12f84181c3451cc752be224643e87fac497b69edddadc49b4f2  gmp.tar.xz"; \
    tar -xf gmp.tar.xz; \
    cd gmp-6.2.1; \
    ./configure --prefix=/usr --enable-shared=no --enable-static=yes; \
    make -j; \
    make install; \
    rm -rf $SRC/gmp-6.2.1; \
    rm -f $SRC/gmp.tar.xz

# libabicoder
RUN set -ex; \
    cd /usr/src; \
    git clone https://github.com/ekpyron/Yul-Isabelle; \
    cd Yul-Isabelle; \
    cd libabicoder; \
    CXX=clang++ CXXFLAGS="-stdlib=libc++ -pthread" make; \
    cp libabicoder.a /usr/lib; \
    cp abicoder.hpp /usr/include; \
    rm -rf /usr/src/Yul-Isabelle

COPY build.sh $SRC/
