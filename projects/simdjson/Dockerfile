# Copyright 2019 Google Inc.
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

RUN apt-get update && apt-get install -y ninja-build wget

# Pre-stage CPM.cmake so the developer-mode build does not need to fetch it
# from github.com/.../releases/download at configure time (that host is not
# reliably reachable from the OSS-Fuzz build network). simdjson's CPM bootstrap
# picks it up from $CPM_SOURCE_CACHE/cpm/CPM_<version>.cmake when the SHA256
# matches, so no download happens.
RUN mkdir -p $SRC/cpm-cache/cpm && \
    wget -q https://github.com/cpm-cmake/CPM.cmake/releases/download/v0.40.2/CPM.cmake \
      -O $SRC/cpm-cache/cpm/CPM_0.40.2.cmake

RUN git clone --depth 1 https://github.com/simdjson/simdjson.git simdjson
WORKDIR simdjson
COPY run_tests.sh build.sh $SRC/

