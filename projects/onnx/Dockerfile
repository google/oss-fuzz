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

FROM gcr.io/oss-fuzz-base/base-builder-python
RUN apt-get update && apt-get install -y cmake protobuf-compiler
RUN pip install "scikit-build-core>=0.11" "nanobind==2.12.0"
RUN git clone --depth 1 https://github.com/onnx/onnx.git onnx && \
    cd onnx && \
    git submodule update --init --recursive
# Pre-download FetchContent dependencies (protobuf + abseil) so the build
# works offline inside the container without network access at cmake time.
RUN mkdir -p /deps/protobuf /deps/abseil-cpp && \
    wget -qO- https://github.com/protocolbuffers/protobuf/releases/download/v25.1/protobuf-25.1.tar.gz | \
        tar -xz --strip-components=1 -C /deps/protobuf && \
    wget -qO- https://github.com/abseil/abseil-cpp/releases/download/20250127.0/abseil-cpp-20250127.0.tar.gz | \
        tar -xz --strip-components=1 -C /deps/abseil-cpp
WORKDIR $SRC
COPY build.sh $SRC/
