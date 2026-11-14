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

FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04

# Build tools and Folly runtime dependencies
RUN apt-get update && apt-get install -y \
    cmake \
    ninja-build \
    pkg-config \
    python3 \
    libboost-all-dev \
    libssl-dev \
    libevent-dev \
    libdouble-conversion-dev \
    libgflags-dev \
    libgoogle-glog-dev \
    libfmt-dev \
    liblz4-dev \
    libzstd-dev \
    libsnappy-dev \
    libbz2-dev \
    zlib1g-dev \
    libunwind-dev \
    libelf-dev

# Clone the upstream repository; fuzz targets live in folly/fuzz/ inside it.
RUN git clone --depth 1 https://github.com/facebook/folly.git $SRC/folly

COPY build.sh $SRC/
