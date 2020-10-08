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
    liblzma-dev uuid-dev pkg-config openjdk-8-jdk unzip

RUN git clone --recursive https://github.com/ethereum/solidity.git solidity
RUN git clone --depth 1 https://github.com/ethereum/solidity-fuzzing-corpus.git
RUN git clone --recursive -b boost-1.69.0 https://github.com/boostorg/boost.git \
    boost
RUN git clone --depth 1 https://github.com/google/libprotobuf-mutator.git
RUN git clone --branch="v0.4.0" --recurse-submodules \
    https://github.com/ethereum/evmone.git

# Install statically built dependencies in "/usr" directory
# Install boost
RUN cd $SRC/boost; \
    ./bootstrap.sh --with-toolset=clang --prefix=/usr; \
    ./b2 clean; \
    ./b2 toolset=clang cxxflags="-stdlib=libc++" linkflags="-stdlib=libc++" \
    headers; \
    ./b2 toolset=clang cxxflags="-stdlib=libc++" linkflags="-stdlib=libc++" \
    link=static variant=release runtime-link=static \
    system regex filesystem unit_test_framework program_options \
    install -j $(($(nproc)/2));

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

# Antlr4 Runtime
RUN set -ex; \
    cd /usr/src; \
    wget https://www.antlr.org/download/antlr4-cpp-runtime-4.8-source.zip; \
    rm -rf antlr4-runtime && mkdir antlr4-runtime; \
    unzip antlr4-cpp-runtime-4.8-source.zip -d antlr4-runtime; \
    cd antlr4-runtime && mkdir build && cd build; \
    cmake .. -DWITH_LIBCXX=On -DCMAKE_BUILD_TYPE=Release -DWITH_DEMO=False; \
    make -j; \
    DESTDIR=run make install; \
    # Manually copy needed library and includes since install script
    # does not respect -DCMAKE_INSTALL_DIR and there is no option
    # to disable shared library build/installation
    cp -Rf run/usr/local/include/antlr4-runtime /usr/include; \
    cp -f run/usr/local/lib/libantlr4-runtime.a /usr/lib; \
    rm -rf /usr/src/antlr4-cpp-runtime-4.8-source.zip; \
    rm -rf /usr/src/antlr4-runtime

COPY build.sh $SRC/
