# Copyright 2020 Google Inc.
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
MAINTAINER neildhar@fb.com
RUN apt-get update && \
    apt-get install -y make autoconf automake libtool wget libicu-dev \
    ninja-build python zip libreadline-dev libatomic-ops-dev
# Install cmake
RUN wget https://github.com/Kitware/CMake/releases/download/v3.16.6/cmake-3.16.6-Linux-x86_64.sh; \
    chmod +x cmake-3.16.6-Linux-x86_64.sh; \
    ./cmake-3.16.6-Linux-x86_64.sh --skip-license --prefix="/usr/local"
RUN git clone https://github.com/facebook/hermes.git
WORKDIR hermes
COPY build.sh $SRC/
