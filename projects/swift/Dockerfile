# Copyright 2021 Google LLC
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
RUN apt-get update && apt install -y  \
    cmake                 \
    icu-devtools          \
    libcurl4-openssl-dev  \
    libedit-dev           \
    libicu-dev            \
    libncurses5-dev       \
    libpython3-dev        \
    libsqlite3-dev        \
    libxml2-dev           \
    ninja-build           \
    pkg-config            \
    python                \
    python-six            \
    rsync                 \
    swig                  \
    systemtap-sdt-dev     \
    tzdata                \
    uuid-dev

RUN git clone --depth 1 https://github.com/apple/swift.git swift-project/swift
RUN cd swift-project/swift && utils/update-checkout --clone
COPY build.sh $SRC
COPY patch.diff $SRC
WORKDIR $SRC/swift-project/swift
