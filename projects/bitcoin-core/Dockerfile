# Copyright 2021 Google LLC
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

# Held back because of github.com/google/oss-fuzz/pull/8313
# Please fix failure and upgrade.
FROM gcr.io/oss-fuzz-base/base-builder-rust@sha256:b942129fbed50e87e554a58dbbbbf90382f17c650dc4d4e27b7a9f8e68b1d494

# Packages taken from:
# * https://github.com/bitcoin/bitcoin/blob/master/doc/build-unix.md#dependency-build-instructions
# * https://github.com/bitcoin/bitcoin/blob/master/depends/README.md#for-linux-including-i386-arm-cross-compilation
RUN apt-get update && apt-get install -y \
  build-essential libtool autotools-dev automake pkg-config bsdmainutils python3 \
  make automake cmake curl g++-multilib libtool binutils-gold bsdmainutils pkg-config patch bison \
  wget zip

RUN git clone --depth=1 https://github.com/bitcoin/bitcoin.git bitcoin-core
RUN git clone --depth=1 https://github.com/bitcoin-core/qa-assets bitcoin-core/assets
RUN git clone --depth 1 https://github.com/guidovranken/cryptofuzz
RUN git clone --depth 1 https://github.com/bitcoin-core/secp256k1.git
RUN git clone --depth 1 https://github.com/randombit/botan.git
RUN git clone --depth 1 https://github.com/trezor/trezor-firmware.git
RUN git clone --depth 1 https://github.com/google/wycheproof.git
RUN wget https://boostorg.jfrog.io/artifactory/main/release/1.74.0/source/boost_1_74_0.tar.bz2
WORKDIR bitcoin-core
COPY build.sh $SRC/
COPY build_cryptofuzz.sh $SRC/
