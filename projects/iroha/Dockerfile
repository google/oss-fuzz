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
RUN git clone --depth 1 https://github.com/hyperledger/iroha.git

WORKDIR iroha

RUN cp -R $SRC/iroha/vcpkg_old /tmp/vcpkg-vars

RUN set -e; \
    git clone https://github.com/microsoft/vcpkg /tmp/vcpkg; \
    (cd /tmp/vcpkg ; git checkout $(cat /tmp/vcpkg-vars/VCPKG_COMMIT_SHA)); \
    for i in /tmp/vcpkg-vars/patches/*.patch; do git -C /tmp/vcpkg apply $i; done; \
    for i in /tmp/vcpkg-vars/patches/oss/*.patch; do git -C /tmp/vcpkg apply $i; done; \
    sh /tmp/vcpkg/bootstrap-vcpkg.sh; \
    /tmp/vcpkg/vcpkg install $(cat /tmp/vcpkg-vars/VCPKG_BOOST_LOCALE_DEPS_LIST | cut -d':' -f1 | tr '\n' ' '); \
    (cd /tmp/vcpkg ; git checkout -- scripts/toolchains/linux.cmake); \
    (cd /tmp/vcpkg ; git apply /tmp/vcpkg-vars/patches/oss/0002-vcpkg-dependencies-flags.patch); \
    /tmp/vcpkg/vcpkg install boost-locale; \
    (cd /tmp/vcpkg ; git apply /tmp/vcpkg-vars/patches/oss/0003-vcpkg-dependencies-sanitizer.patch); \
    /tmp/vcpkg/vcpkg install $(sed 's/grpc://' /tmp/vcpkg-vars/VCPKG_DEPS_LIST | cut -d':' -f1 | tr '\n' ' '); \
    bash -c 'function bumper { while sleep 1; do echo bump; done; }; function run_with_bumper { bumper & p=$!; $@; kill $p; }; ASAN_OPTIONS=detect_leaks=0 run_with_bumper /tmp/vcpkg/vcpkg install grpc'; \ 
    /tmp/vcpkg/vcpkg install --head $(cat /tmp/vcpkg-vars/VCPKG_HEAD_DEPS_LIST | cut -d':' -f1 | tr '\n' ' '); \
    /tmp/vcpkg/vcpkg export $(/tmp/vcpkg/vcpkg list | cut -d':' -f1 | tr '\n' ' ') --raw --output=dependencies; \
    mv /tmp/vcpkg/dependencies /opt/dependencies; \
    chmod +x /opt/dependencies/installed/x64-linux/tools/protobuf/protoc*; \
    rm -rf /tmp/vcpkg*

COPY build.sh $SRC/
