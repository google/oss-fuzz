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
MAINTAINER tsdgeos@gmail.com
RUN apt-get update && apt-get install --yes cmake

# libical requires cmake 3.11 whereas Ubuntu 16.04 only has 3.5.1
ADD https://github.com/Kitware/CMake/releases/download/v3.14.3/cmake-3.14.3-Linux-x86_64.tar.gz $WORK
RUN cd $WORK && tar -xzf cmake-3.14.3-Linux-x86_64.tar.gz && rm cmake-3.14.3-Linux-x86_64.tar.gz

RUN git clone --depth 1 https://github.com/libical/libical.git
COPY build.sh $SRC
COPY libical_fuzzer.cc $SRC
WORKDIR libical



