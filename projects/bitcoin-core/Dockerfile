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

FROM gcr.io/oss-fuzz-base/base-builder

# Packages taken from:
# * https://github.com/bitcoin/bitcoin/blob/master/doc/build-unix.md#dependency-build-instructions
# * https://github.com/bitcoin/bitcoin/blob/master/depends/README.md#for-linux-including-i386-arm-cross-compilation
RUN apt-get update && apt-get install -y \
  build-essential curl g++-multilib make \
  patch pkgconf python3 wget zip

RUN git clone --depth=1 https://github.com/bitcoin/bitcoin.git bitcoin-core
RUN git clone --depth=1 https://github.com/bitcoin-core/qa-assets bitcoin-core/assets && \
  rm -rf bitcoin-core/assets/.git  # Remove git history to save storage
RUN git clone --depth 1 https://github.com/bitcoin-core/secp256k1.git
WORKDIR bitcoin-core
COPY build.sh $SRC/
