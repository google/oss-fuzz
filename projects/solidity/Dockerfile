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
    build-essential libbz2-dev ninja-build zlib1g-dev wget python python-dev
# Install cmake 3.14 (minimum requirement is cmake 3.10)
RUN wget https://github.com/Kitware/CMake/releases/download/v3.14.5/cmake-3.14.5-Linux-x86_64.sh; \
    chmod +x cmake-3.14.5-Linux-x86_64.sh; \
    ./cmake-3.14.5-Linux-x86_64.sh --skip-license --prefix="/usr"

RUN git clone --recursive https://github.com/ethereum/solidity.git solidity
RUN git clone --depth 1 https://github.com/ethereum/solidity-fuzzing-corpus.git
RUN git clone --recursive -b boost-1.69.0 https://github.com/boostorg/boost.git \
    boost
RUN git clone --depth 1 https://github.com/google/libprotobuf-mutator.git
RUN git clone --branch="v0.4.0" --recurse-submodules \
    https://github.com/ethereum/evmone.git
RUN git clone --branch="z3-4.8.7" https://github.com/Z3Prover/z3.git

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

# Install Z3
RUN cd $SRC/z3; \
    mkdir -p build; \
    cd build; \
    LDFLAGS=$CXXFLAGS cmake -DZ3_BUILD_LIBZ3_SHARED=OFF -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release ..; \
    make libz3 -j; \
    make install;

COPY build.sh $SRC/
