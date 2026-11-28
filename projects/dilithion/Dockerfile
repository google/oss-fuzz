# Copyright 2025 Google LLC
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

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libleveldb-dev \
    libssl-dev \
    libboost-test-dev \
    git \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Clone and build RandomX dependency
RUN git clone --depth 1 https://github.com/tevador/RandomX.git /randomx && \
    cd /randomx && \
    mkdir -p build && cd build && \
    cmake .. && \
    make -j$(nproc)

# Clone and build Dilithium dependency
RUN git clone --depth 1 https://github.com/pq-crystals/dilithium.git /dilithium && \
    cd /dilithium/ref && \
    make clean && \
    CC=clang CFLAGS="-O1 -g -DDILITHIUM_MODE=3" make -j$(nproc)

# Copy source code
COPY . /src/dilithion
WORKDIR /src/dilithion

# Set environment variables for build
ENV RANDOMX_BUILD_DIR=/randomx/build
ENV DILITHIUM_DIR=/dilithium/ref
