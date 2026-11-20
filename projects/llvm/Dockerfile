# Copyright 2017 Google Inc.
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
RUN apt-get update -y && \
    apt-get install -y autoconf automake libtool curl make g++ unzip wget git \
    binutils liblzma-dev libz-dev python-all ninja-build subversion \
    pkg-config

# LLVM's top-level CMakeLists.txt requires CMake >= 3.31.0, which is newer than
# the version shipped in the base-builder's apt repositories. Install a recent
# CMake into /opt/cmake and put it first on PATH.
RUN mkdir -p /opt/cmake && \
    curl -L https://github.com/Kitware/CMake/releases/download/v3.31.8/cmake-3.31.8-linux-x86_64.tar.gz | \
    tar xzf - -C /opt/cmake --strip-components 1
ENV PATH="/opt/cmake/bin:${PATH}"

RUN git clone --depth 1 https://github.com/llvm/llvm-project.git

RUN git clone --depth 1 https://github.com/AdaLogics/ada-fuzzers && \
    $SRC/ada-fuzzers/projects/llvm/copy-over.sh

COPY build.sh *.py $SRC/
