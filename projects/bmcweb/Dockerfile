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

RUN apt-get update && apt-get install -y \
    pkg-config \
    cmake \
    python3-pip \
    libpam0g-dev \
    libsystemd-dev \
    zlib1g-dev \
    libzstd-dev

RUN pip3 install -U meson ninja inflection pyyaml mako

RUN git clone --depth 1 https://github.com/openbmc/bmcweb $SRC/bmcweb

COPY build.sh $SRC/
COPY *_fuzzer.cpp $SRC/

WORKDIR $SRC/bmcweb
