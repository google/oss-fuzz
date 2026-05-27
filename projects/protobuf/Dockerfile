# Copyright 2024 Google LLC
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

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        cmake \
        ninja-build \
        python3 \
        curl \
        unzip \
        openjdk-11-jdk-headless && \
    rm -rf /var/lib/apt/lists/*

# Install Bazel (needed by some protobuf build paths)
RUN curl -fsSL https://github.com/bazelbuild/bazelisk/releases/download/v1.19.0/bazelisk-linux-amd64 \
        -o /usr/local/bin/bazel && \
    chmod +x /usr/local/bin/bazel

RUN git clone --depth 1 https://github.com/protocolbuffers/protobuf.git $SRC/protobuf

WORKDIR $SRC/protobuf

COPY build.sh proto_decode_fuzzer.cc proto_json_fuzzer.cc $SRC/
