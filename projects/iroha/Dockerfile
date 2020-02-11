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
MAINTAINER konstantin@soramitsu.co.jp
  
RUN set -e; \
    apt-get update && \
    apt-get -y --no-install-recommends install libicu-dev \
        apt-utils git curl wget unzip tar; \
    apt-get -y clean
     
RUN wget https://github.com/Kitware/CMake/releases/download/v3.14.4/cmake-3.14.4-Linux-x86_64.tar.gz && tar -xzvf cmake-3.14.4-Linux-x86_64.tar.gz && cp -a cmake-3.14.4-Linux-x86_64/bin/. /usr/bin/ && cp -a cmake-3.14.4-Linux-x86_64/share/. /usr/share/
  
  
# Get *your* source code here.
RUN git clone --depth 1 --single-branch --branch master https://github.com/hyperledger/iroha.git

WORKDIR iroha

RUN cp -R $SRC/iroha/vcpkg /tmp/vcpkg-vars

RUN ["bash", "/tmp/vcpkg-vars/oss/build_deps.sh"]

COPY build.sh $SRC/
