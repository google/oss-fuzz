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

FROM gcr.io/oss-fuzz-base/base-builder-rust

ENV GOPATH /root/go
ENV PATH $PATH:/root/.go/bin:$GOPATH/bin
RUN install_go.sh

RUN apt-get update && \
    apt-get install -y software-properties-common wget make autoconf automake libtool build-essential cmake mercurial gyp ninja-build zlib1g-dev libsqlite3-dev bison flex texinfo lzip bsdmainutils

RUN git clone --depth 1 https://github.com/guidovranken/cryptofuzz
RUN git clone --depth 1 https://github.com/guidovranken/cryptofuzz-corpora
RUN git clone --depth 1 https://github.com/openssl/openssl
RUN git clone --depth 1 https://boringssl.googlesource.com/boringssl
RUN git clone --depth 1 https://github.com/weidai11/cryptopp/
RUN git clone --depth 1 git://git.gnupg.org/libgcrypt.git
RUN wget https://gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-1.36.tar.bz2
RUN git clone --depth 1 -b oss-fuzz https://github.com/project-everest/hacl-star evercrypt
RUN git clone --depth 1 https://github.com/google/cityhash.git
RUN git clone --depth 1 https://github.com/randombit/botan.git
RUN git clone --depth 1 https://github.com/wolfSSL/wolfssl.git
RUN git clone --depth 1 -b development https://github.com/Mbed-TLS/mbedtls.git
RUN hg clone https://hg.mozilla.org/projects/nspr
RUN hg clone https://hg.mozilla.org/projects/nss
RUN git clone --depth 1 https://github.com/jedisct1/libsodium.git
RUN git clone --depth 1 https://github.com/libtom/libtomcrypt.git
RUN git clone --depth 1 https://github.com/microsoft/SymCrypt.git
RUN hg clone https://gmplib.org/repo/gmp/ libgmp/
RUN wget https://www.bytereef.org/software/mpdecimal/releases/mpdecimal-2.5.1.tar.gz
RUN git clone --depth 1 https://github.com/indutny/bn.js.git
RUN git clone --depth 1 https://github.com/MikeMcl/bignumber.js.git
RUN git clone --depth 1 https://github.com/guidovranken/libfuzzer-js.git
RUN git clone --depth 1 https://github.com/brix/crypto-js.git
RUN git clone --depth 1 https://github.com/trezor/trezor-firmware.git
RUN git clone --depth 1 https://github.com/Cyan4973/xxHash.git
RUN git clone --depth 1 https://github.com/paulmillr/noble-ed25519.git
RUN git clone --depth 1 https://github.com/paulmillr/noble-bls12-381.git
RUN git clone --depth 1 https://github.com/paulmillr/noble-secp256k1.git
RUN git clone --depth 1 https://github.com/supranational/blst.git
RUN git clone --depth 1 https://github.com/bitcoin-core/secp256k1.git
RUN apt-get remove -y libunwind8
RUN apt-get install -y libssl-dev
RUN wget https://boostorg.jfrog.io/artifactory/main/release/1.74.0/source/boost_1_74_0.tar.bz2
RUN wget https://nodejs.org/dist/v14.17.1/node-v14.17.1-linux-x64.tar.xz
RUN wget https://download.java.net/java/GA/jdk18.0.1/3f48cabb83014f9fab465e280ccf630b/10/GPL/openjdk-18.0.1_linux-x64_bin.tar.gz
RUN pip3 install -r $SRC/mbedtls/scripts/basic.requirements.txt
RUN bash -c "wget $(curl https://ziglang.org/download/index.json | jq -r '.master."x86_64-linux".tarball') -O zig-latest.tar.xz"

COPY build.sh xxd.c $SRC/
