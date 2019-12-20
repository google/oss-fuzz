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

RUN apt-get update && apt-get install -y software-properties-common python-software-properties make autoconf automake libtool build-essential cmake libboost-all-dev wget mercurial gyp ninja-build zlib1g-dev libsqlite3-dev

# BoringSSL needs Go to build
RUN add-apt-repository -y ppa:gophers/archive && apt-get update && apt-get install -y golang-1.9-go
RUN ln -s /usr/lib/go-1.9/bin/go /usr/bin/go

RUN git clone --depth 1 https://github.com/guidovranken/cryptofuzz
RUN git clone --depth 1 https://github.com/guidovranken/cryptofuzz-corpora
RUN git clone --depth 1 https://github.com/openssl/openssl

RUN git clone --depth 1 https://boringssl.googlesource.com/boringssl
RUN git clone --depth 1 https://github.com/libressl-portable/portable libressl
RUN cd $SRC/libressl && ./update.sh
RUN git clone --depth 1 https://github.com/weidai11/cryptopp/
RUN git clone --depth 1 https://dev.gnupg.org/source/libgcrypt.git
RUN wget https://gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-1.36.tar.bz2
RUN git clone --depth 1 -b oss-fuzz https://github.com/project-everest/hacl-star evercrypt
RUN git clone --depth 1 https://github.com/google/cityhash.git
RUN git clone --depth 1 https://github.com/golang/go
RUN git clone --depth 1 https://github.com/randombit/botan.git
RUN git clone --depth 1 https://github.com/wolfSSL/wolfssl.git
RUN git clone --depth 1 https://github.com/ARMmbed/mbed-crypto.git
RUN hg clone https://hg.mozilla.org/projects/nspr
RUN hg clone https://hg.mozilla.org/projects/nss
RUN apt-get remove -y libunwind8

COPY build.sh $SRC/
