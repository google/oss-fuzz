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
RUN apt-get update && apt-get install -y make autoconf automake libtool
RUN apt-get install -y cmake libpcsclite-dev libudev-dev pkg-config chrpath
RUN git clone --depth 1 --branch v0.9.0 https://github.com/PJK/libcbor
RUN git clone --depth 1 --branch OpenSSL_1_1_1-stable https://github.com/openssl/openssl
RUN git clone --depth 1 --branch v1.2.11 https://github.com/madler/zlib
RUN git clone --depth 1 https://github.com/Yubico/libfido2
# CIFuzz will replace the libfido directory so put the corpus outside
ADD https://storage.googleapis.com/yubico-libfido2/corpus.tgz corpus.tgz
WORKDIR libfido2
COPY build.sh $SRC/
