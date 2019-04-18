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
MAINTAINER guidovranken@gmail.com

RUN apt-get update && apt-get install -y software-properties-common python-software-properties make autoconf automake libtool build-essential cmake

# BoringSSL needs Go to build
RUN add-apt-repository -y ppa:gophers/archive && apt-get update && apt-get install -y golang-1.9-go
RUN ln -s /usr/lib/go-1.9/bin/go /usr/bin/go

RUN git clone --depth 1 https://github.com/guidovranken/cryptofuzz
RUN git clone --depth 1 https://github.com/guidovranken/cryptofuzz-corpora
RUN git clone https://github.com/openssl/openssl

# The OpenSSL build system is currently broken, see also: https://github.com/google/oss-fuzz/issues/2314
# Lock OpenSSL to an older commit that does not cause build problems.
# This should be removed as soon as OpenSSL's build system is repaired.
RUN cd openssl && git checkout 9efa0ae0b602c1c0e356009a58410a2e8b80201a

RUN git clone --depth 1 https://boringssl.googlesource.com/boringssl
RUN git clone --depth 1 https://github.com/libressl-portable/portable libressl
RUN cd $SRC/libressl && ./update.sh

COPY build.sh $SRC/
