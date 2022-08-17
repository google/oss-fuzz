# Copyright 2016 Google Inc.
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

# Docker image with head clang installed.

FROM gcr.io/oss-fuzz-base/base-image

ARG arch=x86_64

ARG introspector
ENV INTROSPECTOR_PATCHES=$introspector
ENV FUZZINTRO_OUTDIR=$SRC
ENV FUZZ_INTROSPECTOR=$introspector

# Install newer cmake.
ENV CMAKE_VERSION 3.21.1
RUN apt-get update && apt-get install -y wget sudo && \
    wget https://github.com/Kitware/CMake/releases/download/v$CMAKE_VERSION/cmake-$CMAKE_VERSION-Linux-$arch.sh && \
    chmod +x cmake-$CMAKE_VERSION-Linux-$arch.sh && \
    ./cmake-$CMAKE_VERSION-Linux-$arch.sh --skip-license --prefix="/usr/local" && \
    rm cmake-$CMAKE_VERSION-Linux-$arch.sh && \
    SUDO_FORCE_REMOVE=yes apt-get remove --purge -y wget sudo && \
    rm -rf /usr/local/doc/cmake /usr/local/bin/cmake-gui

RUN apt-get update && apt-get install -y git && \
    git clone https://github.com/ossf/fuzz-introspector.git fuzz-introspector && \
    cd fuzz-introspector && \
    git checkout 11364ead46a8f01318e506d2a3490aea7e236901 && \
    apt-get remove --purge -y git

COPY checkout_build_install_llvm.sh /root/
# Keep all steps in the same script to decrease the number of intermediate
# layes in docker file.
RUN /root/checkout_build_install_llvm.sh
RUN rm /root/checkout_build_install_llvm.sh

# Setup the environment.
ENV CC "clang"
ENV CXX "clang++"
ENV CCC "clang++"

# FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION is described at
# http://libfuzzer.info#fuzzer-friendly-build-mode

ENV CFLAGS "-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
ENV CXXFLAGS_EXTRA "-stdlib=libc++"
ENV CXXFLAGS "$CFLAGS $CXXFLAGS_EXTRA"
