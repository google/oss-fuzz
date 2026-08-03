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

FROM gcr.io/oss-fuzz-base/base-builder

# Install Bazel (TF Serving's build system)
ENV BAZEL_VERSION=6.4.0
RUN apt-get update && apt-get install -y \
    curl \
    git \
    python3 \
    python3-pip \
    unzip \
    wget \
    zip \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL \
    "https://github.com/bazelbuild/bazel/releases/download/${BAZEL_VERSION}/bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh" \
    -o /tmp/bazel_installer.sh \
    && chmod +x /tmp/bazel_installer.sh \
    && /tmp/bazel_installer.sh \
    && rm /tmp/bazel_installer.sh

# Clone tensorflow/serving at latest master
RUN git clone --depth=1 https://github.com/tensorflow/serving.git /src/tensorflow-serving

WORKDIR /src/tensorflow-serving

# Copy the fuzz target and build script
COPY json_tensor_fuzzer.cc tensorflow_serving/util/json_tensor_fuzzer.cc
COPY build.sh $SRC/

# Seed corpus: valid predict/classify/regress JSON payloads
