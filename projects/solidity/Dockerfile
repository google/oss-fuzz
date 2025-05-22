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

FROM gcr.io/oss-fuzz-base/base-builder@sha256:19782f7fe8092843368894dbc471ce9b30dd6a2813946071a36e8b05f5b1e27e
# ! This project was pinned after a clang bump. Please remove the pin, Try to fix any build warnings and errors, as well as runtime errors
RUN apt-get update && apt-get install -y make autoconf automake libtool \
    build-essential libbz2-dev ninja-build zlib1g-dev wget python python-dev \
    liblzma-dev uuid-dev pkg-config openjdk-8-jdk unzip mlton bison texinfo

RUN git clone --recursive -b develop https://github.com/ethereum/solidity.git solidity
RUN git clone --depth 1 https://github.com/ethereum/solidity-fuzzing-corpus.git
RUN git clone https://github.com/google/libprotobuf-mutator.git
RUN git clone --branch="v0.11.0" --recurse-submodules \
    https://github.com/ethereum/evmone.git

# Install statically built dependencies in "/usr" directory
# Install boost
RUN cd $SRC && \
    wget -q 'https://archives.boost.io/release/1.83.0/source/boost_1_83_0.tar.bz2' -O boost.tar.bz2 && \
    test "$(sha256sum boost.tar.bz2)" = "6478edfe2f3305127cffe8caf73ea0176c53769f4bf1585be237eb30798c3b8e  boost.tar.bz2" && \
    tar -xf boost.tar.bz2 && \
    rm boost.tar.bz2 && \
    cd boost_1_83_0 && \
    CXXFLAGS="-stdlib=libc++ -pthread" LDFLAGS="-stdlib=libc++" ./bootstrap.sh --with-toolset=clang --prefix=/usr && \
    ./b2 toolset=clang cxxflags="-stdlib=libc++ -pthread" linkflags="-stdlib=libc++ -pthread" headers && \
    ./b2 toolset=clang cxxflags="-stdlib=libc++ -pthread" linkflags="-stdlib=libc++ -pthread" \
        link=static variant=release runtime-link=static \
        system filesystem unit_test_framework program_options \
        install -j $(($(nproc)/2)) && \
    rm -rf $SRC/boost_1_83_0

# Install libprotobuf-mutator
# Use commit prior to libprotobuf upgrade that broke solidity build
# See https://github.com/google/oss-fuzz/issues/10237
RUN cd $SRC/libprotobuf-mutator; \
    git reset --hard 212a7be1eb08e7f9c79732d2aab9b2097085d936; \
    mkdir $SRC/LPM; \
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
    ninja install/strip;

# gmp
RUN cd $SRC; \
    # Replace system installed libgmp static library
    # with sanitized version
    git clone --depth 1 --branch gmp-6.2.1 https://github.com/gmp-mirror/gmp-6.2 gmp/; \
    rm -r gmp/.git/; \
    test \
        "$(tar --create gmp/ --sort=name --mtime=1970-01-01Z --owner=0 --group=0 --numeric-owner | sha256sum)" = \
        "d606ff6a4ce98692f9920031e85ea8fcf4a65ce1426f6f0048b8794aefed174b  -"; \
    # NOTE: This removes also libgmp.so, which git depends on
    rm -f /usr/lib/x86_64-linux-gnu/libgmp.*; \
    rm -f /usr/include/x86_64-linux-gnu/gmp.h; \
    cd gmp; \
    autoreconf -i; \
    ./configure --prefix=/usr --enable-static=yes --enable-maintainer-mode; \
    make -j; \
    make check; \
    make install; \
    rm -rf $SRC/gmp;

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
