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
RUN apt-get update -y
RUN apt-get install -y autoconf automake libtool curl make g++ unzip wget git \
    binutils liblzma-dev libz-dev python-all ninja-build subversion \
    pkg-config

# Pulling newer version of CMake because currently llvm-libc needs minimum cmake 3.13
ADD https://github.com/Kitware/CMake/releases/download/v3.15.7/cmake-3.15.7-Linux-x86_64.sh /cmake-3.15.7-Linux-x86_64.sh
RUN mkdir /opt/cmake
RUN sh /cmake-3.15.7-Linux-x86_64.sh --prefix=/opt/cmake --skip-license
RUN ln -s /opt/cmake/bin/cmake /usr/local/bin/cmake
RUN cmake --version

# Get LLVM
RUN git clone --depth 1 https://github.com/llvm/llvm-project.git

COPY build.sh $SRC/
