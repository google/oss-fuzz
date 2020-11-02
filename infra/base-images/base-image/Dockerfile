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

# Base image for all other images.

FROM ubuntu:16.04
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y libc6-dev binutils libgcc-5-dev && \
    apt-get autoremove -y

ENV OUT=/out
ENV SRC=/src
ENV WORK=/work
ENV PATH="$PATH:/out"

RUN mkdir -p $OUT $SRC $WORK && chmod a+rwx $OUT $SRC $WORK

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
