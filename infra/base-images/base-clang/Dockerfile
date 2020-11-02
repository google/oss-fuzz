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

# Install newer cmake.
ENV CMAKE_VERSION 3.18.1
RUN apt-get update && apt-get install -y wget sudo && \
    wget https://github.com/Kitware/CMake/releases/download/v$CMAKE_VERSION/cmake-$CMAKE_VERSION-Linux-x86_64.sh && \
    chmod +x cmake-$CMAKE_VERSION-Linux-x86_64.sh && \
    ./cmake-$CMAKE_VERSION-Linux-x86_64.sh --skip-license --prefix="/usr/local" && \
    rm cmake-$CMAKE_VERSION-Linux-x86_64.sh && \
    SUDO_FORCE_REMOVE=yes apt-get remove --purge -y wget sudo

# Steps for ARM cross-compilation

RUN apt-get install qemu-user wget xz-utils -y && \
    cd /opt && \
    wget https://releases.linaro.org/components/toolchain/binaries/7.5-2019.12/aarch64-linux-gnu/gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu.tar.xz && \
    tar xJvf gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu.tar.xz && \
    rm gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu.tar.xz && \
    apt-get remove --purge -y wget xz-utils

ENV AARCH64_TOOLCHAIN /opt/gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu
ENV AARCH64_SYSROOT="$AARCH64_TOOLCHAIN/aarch64-linux-gnu/libc"
ENV QEMU_LD_PREFIX=$AARCH64_SYSROOT
ENV AARCH64_EXTRA_CFLAGS="--target=aarch64-linux-gnu --gcc-toolchain=$AARCH64_TOOLCHAIN --sysroot=$AARCH64_SYSROOT"
ENV AARCH64_TARGET_TRIPLE="aarch64-linux-gnu"

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