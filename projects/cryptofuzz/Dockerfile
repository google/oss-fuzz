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

RUN apt-get update && \
    apt-get install -y apt-transport-https ca-certificates gnupg software-properties-common wget && \
    wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | apt-key add - && \
    apt-add-repository 'deb https://apt.kitware.com/ubuntu/ xenial main' && \
    apt-get update && \
    apt-get install -y software-properties-common python-software-properties make autoconf automake libtool build-essential cmake mercurial gyp ninja-build zlib1g-dev libsqlite3-dev bison flex texinfo

RUN git clone --depth 1 https://github.com/guidovranken/cryptofuzz
RUN git clone --depth 1 https://github.com/guidovranken/cryptofuzz-corpora
RUN git clone --depth 1 https://github.com/openssl/openssl
RUN git clone --depth 1 https://boringssl.googlesource.com/boringssl
RUN git clone --depth 1 https://github.com/libressl-portable/portable libressl
RUN cd $SRC/libressl && ./update.sh
RUN git clone --depth 1 https://github.com/weidai11/cryptopp/
RUN git clone --depth 1 git://git.gnupg.org/libgcrypt.git
RUN wget https://gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-1.36.tar.bz2
RUN git clone --depth 1 -b oss-fuzz https://github.com/project-everest/hacl-star evercrypt
RUN git clone --depth 1 https://github.com/google/cityhash.git
RUN git clone --depth 1 https://github.com/randombit/botan.git
RUN git clone --depth 1 https://github.com/wolfSSL/wolfssl.git
RUN git clone --depth 1 -b development_2.x https://github.com/ARMmbed/mbedtls.git
RUN hg clone https://hg.mozilla.org/projects/nspr
RUN hg clone https://hg.mozilla.org/projects/nss
RUN git clone --depth 1 https://github.com/jedisct1/libsodium.git
RUN git clone --depth 1 https://github.com/libtom/libtomcrypt.git
RUN git clone --depth 1 https://github.com/microsoft/SymCrypt.git
RUN git clone --depth 1 https://git.lysator.liu.se/nettle/nettle
RUN hg clone https://gmplib.org/repo/gmp/ libgmp/
RUN wget https://www.bytereef.org/software/mpdecimal/releases/mpdecimal-2.5.0.tar.gz
RUN git clone --depth 1 https://github.com/indutny/bn.js.git
RUN git clone --depth 1 https://github.com/MikeMcl/bignumber.js.git
RUN git clone --depth 1 https://github.com/guidovranken/libfuzzer-js.git
RUN git clone --depth 1 https://github.com/brix/crypto-js.git
RUN git clone --depth 1 https://github.com/LoupVaillant/Monocypher.git
RUN git clone --depth 1 https://github.com/trezor/trezor-firmware.git
RUN git clone --depth 1 https://github.com/Cyan4973/xxHash.git
RUN apt-get remove -y libunwind8
RUN apt-get install -y libssl-dev
RUN wget https://boostorg.jfrog.io/artifactory/main/release/1.74.0/source/boost_1_74_0.tar.bz2

COPY build.sh xxd.c $SRC/
