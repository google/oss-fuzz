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
RUN \
        apt-get update && \
        apt-get install -y \
        make autoconf automake libtool \
        libstdc++-9-dev \
        libseccomp-dev pkg-config && \
        apt-get remove -y libssl-dev || true

# Build OpenSSL 3.x from source (libtpms requires OpenSSL 3.0+ APIs)
# Use no-shared to build static libraries only for proper fuzzer linking
RUN git clone --depth 1 --branch openssl-3.0 https://github.com/openssl/openssl.git /tmp/openssl && \
    cd /tmp/openssl && \
    ./Configure --prefix=/usr --openssldir=/etc/ssl --libdir=lib/x86_64-linux-gnu no-shared && \
    make -j$(nproc) && \
    make install_sw install_ssldirs && \
    rm -rf /tmp/openssl

RUN git clone --depth 1 https://github.com/stefanberger/libtpms libtpms
WORKDIR libtpms
COPY build.sh $SRC/
