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
# OSS-Fuzz Dockerfile for tflite-micro

FROM gcr.io/oss-fuzz-base/base-builder

# Install build dependencies required by tflite-micro's Makefile
RUN apt-get update && apt-get install -y \
    make \
    wget \
    curl \
    unzip \
    python3 \
    python3-pip \
    git \
    xxd \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages that TFLM's build scripts require:
#   numpy  - generate_cc_arrays.py
#   Pillow - generate_cc_arrays.py (PIL image handling)
#   wave   - stdlib, but ensure it's available
RUN pip3 install numpy Pillow flatbuffers --break-system-packages 2>/dev/null \
    || pip3 install numpy Pillow flatbuffers

# Clone tflite-micro repository
RUN git clone --depth 1 https://github.com/tensorflow/tflite-micro.git \
    $SRC/tflite-micro

# Copy the fuzz target source and PoC generators
COPY fuzz_model_load.cc $SRC/
COPY build_malicious_gather.py $SRC/

# Copy seed corpus directory
COPY seed_corpus/ $SRC/seed_corpus/

# Copy build script
COPY build.sh $SRC/

WORKDIR $SRC/tflite-micro
