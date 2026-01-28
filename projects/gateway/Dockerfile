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

FROM gcr.io/oss-fuzz-base/base-builder-go

RUN apt-get update \
    && apt-get install -y btrfs-progs libbtrfs-dev

RUN git clone --depth 1 https://github.com/envoyproxy/gateway.git

RUN cd $SRC/gateway && \
    GO_VERSION=$(grep -oP '^go \K[0-9]+\.[0-9]+(\.[0-9]+)?' go.mod | head -1) && \
    wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
    mkdir temp-go && \
    rm -rf /root/.go/* && \
    tar -C temp-go/ -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    mv temp-go/go/* /root/.go/ && \
    rm -rf temp-go go${GO_VERSION}.linux-amd64.tar.gz

COPY build.sh default.options $SRC/