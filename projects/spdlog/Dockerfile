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
MAINTAINER security-tps@google.com

RUN apt-get update && apt-get install -y make autoconf automake libtool
RUN apt-get update && apt-get install --yes cmake
ADD https://github.com/Kitware/CMake/releases/download/v3.14.3/cmake-3.14.3-Linux-x86_64.tar.gz $WORK
RUN cd $WORK && tar -xzf cmake-3.14.3-Linux-x86_64.tar.gz && rm cmake-3.14.3-Linux-x86_64.tar.gz

RUN git clone --depth 1 https://github.com/gabime/spdlog.git
WORKDIR spdlog
COPY FuzzedDataProvider.h $SRC/
COPY build.sh log_fuzzer.cc $SRC/
