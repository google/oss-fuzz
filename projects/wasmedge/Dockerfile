# Copyright 2023 Google LLC
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

RUN apt-get update && apt-get install -y \
    software-properties-common \
    dpkg-dev \
    ninja-build \
    llvm-12-dev \
    liblld-12-dev

ADD "https://api.github.com/repos/WasmEdge/WasmEdge/commits?per_page=1" latest_commit
RUN rm latest_commit
RUN git clone  https://github.com/WasmEdge/WasmEdge.git

ADD "https://api.github.com/repos/second-state/WasmEdge-unittest/commits?per_page=1&sha=wasm-dev-0.11.0" latest_commit
RUN rm latest_commit
RUN git clone --branch wasm-dev-0.11.0 https://github.com/second-state/WasmEdge-unittest.git

COPY build.sh $SRC/
WORKDIR $SRC
