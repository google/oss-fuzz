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

# Install build dependencies (cmake and ninja are pre-installed in base-builder)
RUN apt-get update && apt-get install -y \
    libssl-dev \
    libboost-dev \
    pkg-config

# Clone Abseil-CPP (LTS release compatible with C++20)
RUN git clone --depth 1 -b 20240116.2 https://github.com/abseil/abseil-cpp.git $SRC/abseil-cpp

# Clone Protobuf v21.12 (matches the 3.21.12 version for compatibility)
RUN git clone --depth 1 -b v21.12 https://github.com/protocolbuffers/protobuf.git $SRC/protobuf && \
    cd $SRC/protobuf && \
    git submodule update --init --recursive

# Clone gPowerD
RUN git clone --depth 1 https://gbmc.googlesource.com/gPowerD gpowerd

WORKDIR gpowerd

COPY build.sh translate_protos.py action_validation_fuzzer.cc condition_fuzzer.cc $SRC/
COPY gpowerd_shims $SRC/gpowerd_shims
