# Copyright 2018 Google Inc.
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
MAINTAINER info@automatak.com
RUN apt-get update && apt-get install -y make wget tshark
# The CMake version that is available on Ubuntu 16.04 is 3.5.1. OpenDNP3
# needs CMake 3.8 or higher, because of the C# bindings. Therefore, we
# manually install a modern CMake until the OSS Fuzz environment updates
# to a more recent Ubuntu.
# This section was taken from JSC Dockerfile
RUN wget -q -O - https://github.com/Kitware/CMake/releases/download/v3.14.4/cmake-3.14.4-Linux-x86_64.sh > /tmp/install_cmake.sh && \
    cd /usr && bash /tmp/install_cmake.sh -- --skip-license && \
    rm /tmp/install_cmake.sh
RUN git clone --recursive -b release-2.x --depth 1 https://github.com/dnp3/opendnp3.git opendnp3
WORKDIR opendnp3
COPY build.sh $SRC/
