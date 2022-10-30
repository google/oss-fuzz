# Copyright 2022 Google LLC
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
RUN apt-get update && apt-get install -y cmake libgflags-dev libprotobuf-dev libprotoc-dev protobuf-compiler libleveldb-dev libgtest-dev libgoogle-perftools-dev libsnappy-dev
RUN git clone --depth 1 https://github.com/apache/incubator-brpc brpc
RUN git clone https://github.com/0x34d/oss-fuzz-bloat
COPY build.sh $SRC/
COPY Fuzz_http.cpp $SRC/brpc/test/Fuzz_http.cpp
COPY Fuzz_json.cpp $SRC/brpc/test/Fuzz_json.cpp
COPY CMakeLists.txt.patch $SRC/brpc/test/CMakeLists.txt.patch
WORKDIR $SRC/brpc/
