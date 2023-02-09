# Copyright 2023 Google LLC
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

RUN apt-get update && apt-get install -y \
  libgoogle-glog-dev libcurl4-openssl-dev libevent-dev \
  libczmq-dev libgmp3-dev libsqlite3-dev \
  libconfig-dev libsctp-dev


RUN curl https://raw.githubusercontent.com/magma/magma/master/keys/linux_foundation_registry_key.asc -o /etc/apt/trusted.gpg.d/magma.asc
RUN echo "deb https://linuxfoundation.jfrog.io/artifactory/magma-packages-test focal-ci main" > /etc/apt/sources.list.d/magma.list

RUN apt-get update && apt-get install -y \
  oai-asn1c oai-nettle oai-gnutls oai-freediameter


RUN git clone --depth 1 https://github.com/0x34d/magma.git

COPY build.sh $SRC/build.sh
COPY build_defs.bzl.patch $SRC/build_defs.bzl.patch
COPY libfluid_base.BUILD.patch $SRC/libfluid_base.BUILD.patch
COPY system_libraries.BUILD.patch $SRC/system_libraries.BUILD.patch

WORKDIR $SRC/magma/
RUN bazel fetch \
  //lte/gateway/c/core/oai/fuzzing/...:*
