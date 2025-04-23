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

# Docker image with clang installed.

FROM gcr.io/oss-fuzz-base/base-image

ARG arch=x86_64

ENV FUZZINTRO_OUTDIR=$SRC

# Install newer cmake.
# Many projects, as well as recent clang versions, need a newer cmake.
ENV CMAKE_VERSION 3.29.2
RUN apt-get update && apt-get install -y wget sudo && \
    wget -q https://github.com/Kitware/CMake/releases/download/v$CMAKE_VERSION/cmake-$CMAKE_VERSION-Linux-$arch.sh && \
    chmod +x cmake-$CMAKE_VERSION-Linux-$arch.sh && \
    ./cmake-$CMAKE_VERSION-Linux-$arch.sh --skip-license --prefix="/usr/local" && \
    rm cmake-$CMAKE_VERSION-Linux-$arch.sh && \
    SUDO_FORCE_REMOVE=yes apt-get autoremove --purge -y wget sudo && \
    rm -rf /usr/local/doc/cmake /usr/local/bin/cmake-gui

RUN apt-get update && apt-get install -y git && \
    git clone https://github.com/ossf/fuzz-introspector.git fuzz-introspector && \
    cd fuzz-introspector && \
    git checkout 8944d0b001754f60a602c95a816880f885f1e38d && \
    git submodule init && \
    git submodule update && \
    apt-get autoremove --purge -y git && \
    rm -rf .git

COPY checkout_build_install_llvm.sh /root/
# Keep all steps in the same script to decrease the number of intermediate
# layes in docker file.
ARG FULL_LLVM_BUILD
RUN FULL_LLVM_BUILD=$FULL_LLVM_BUILD /root/checkout_build_install_llvm.sh
RUN rm /root/checkout_build_install_llvm.sh

# Setup the environment.
ENV CC "clang"
ENV CXX "clang++"
ENV CCC "clang++"

# FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION is described at
# https://llvm.org/docs/LibFuzzer.html#fuzzer-friendly-build-mode

# The implicit-function-declaration and implicit-int errors are downgraded to a
# warning, to allow compiling legacy code.
# See https://releases.llvm.org/16.0.0/tools/clang/docs/ReleaseNotes.html#potentially-breaking-changes
# Same for deprecated-declarations, int-conversion,
# incompatible-function-pointer-types, enum-constexpr-conversion,
# vla-cxx-extension

ENV CFLAGS -O1 \
  -fno-omit-frame-pointer \
  -gline-tables-only \
  -Wno-error=enum-constexpr-conversion \
  -Wno-error=incompatible-function-pointer-types \
  -Wno-error=int-conversion \
  -Wno-error=deprecated-declarations \
  -Wno-error=implicit-function-declaration \
  -Wno-error=implicit-int \
  -Wno-error=vla-cxx-extension \
  -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
ENV CXXFLAGS_EXTRA "-stdlib=libc++"
ENV CXXFLAGS "$CFLAGS $CXXFLAGS_EXTRA"
