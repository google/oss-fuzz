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

FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04

RUN apt-get update && apt-get install -y --no-install-recommends \
    ninja-build \
    pkg-config \
    libsctp-dev \
    libyaml-cpp-dev

# MbedTLS is built from source in build.sh rather than installed from apt, so
# that it carries the same sanitizer instrumentation as the fuzz targets. MSan
# otherwise reports every key derived through it as uninitialized. Pinned to
# the version Ubuntu 24.04 ships, so the targets keep the non-PSA code path.
RUN git clone --depth 1 --branch v2.28.8 https://github.com/Mbed-TLS/mbedtls.git mbedtls
RUN git clone --depth 1 https://gitlab.com/ocudu/ocudu.git ocudu
WORKDIR ocudu
COPY build.sh $SRC/