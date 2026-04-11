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
FROM gcr.io/oss-fuzz-base/base-builder

# Build deps. OCCT's IGES/STEP parser (TKDEIGES) depends on TKService which
# requires X11 headers even when Visualization is disabled, so we install
# libx11-dev, libxext-dev, and libxi-dev.
RUN apt-get update && apt-get install -y --no-install-recommends \
    make \
    cmake \
    git \
    ca-certificates \
    libx11-dev \
    libxext-dev \
    libxi-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/Open-Cascade-SAS/OCCT.git $SRC/occt

# Fuzzer harness, dictionary, seed-corpus generator, and build script all
# live alongside this Dockerfile in the OSS-Fuzz repo and get copied in.
COPY build.sh $SRC/
COPY occt_fuzz_iges.cpp $SRC/
COPY occt_fuzz_iges.dict $SRC/
COPY occt_fuzz_iges_seedgen.py $SRC/

WORKDIR $SRC/occt
