# Copyright 2026 Google LLC
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

FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    autoconf \
    automake \
    bzip2 \
    busybox-static \
    cmake \
    libacl1-dev \
    libarchive-dev \
    libbrotli-dev \
    libbz2-dev \
    liblz4-dev \
    liblzma-dev \
    libsodium-dev \
    libsqlite3-dev \
    libssl-dev \
    libtool \
    libxml2-dev \
    libzstd-dev \
    make \
    ninja-build \
    nlohmann-json3-dev \
    pkg-config \
    python3-pip \
    wget \
    zip \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --break-system-packages meson==1.10.2

# Boost's build system does not search the target-specific libc++ directory.
RUN cp /usr/local/include/x86_64-unknown-linux-gnu/c++/v1/__config_site \
    /usr/local/include/c++/v1/

# Ubuntu 24.04 provides older versions than Nix currently requires.
RUN wget -q \
    https://archives.boost.io/release/1.87.0/source/boost_1_87_0.tar.bz2 \
    -O $SRC/boost_1_87_0.tar.bz2
RUN git clone --depth 1 --branch curl-8_17_0 \
    https://github.com/curl/curl.git $SRC/curl
RUN git clone --depth 1 --branch 1.8.2 \
    https://github.com/BLAKE3-team/BLAKE3.git $SRC/blake3
RUN git clone --depth 1 https://github.com/NixOS/nix.git $SRC/nix

WORKDIR $SRC/nix
COPY build.sh $SRC/
