# Copyright 2021 Google Inc.
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
RUN sed -i -e '/^#\s*deb-src.*\smain\s\+restricted/s/^#//' /etc/apt/sources.list && \
    apt-get update && \
    # libelf build dependencies \
    apt-get build-dep -y --no-install-recommends libelf-dev && \
    apt-get install -y --no-install-recommends pkg-config && \
    # libbpf build dependencies \
    apt-get install -y --no-install-recommends libz-dev libz-dev:i386
RUN git clone --depth 1 https://github.com/libbpf/libbpf
WORKDIR libbpf
COPY build.sh $SRC/
