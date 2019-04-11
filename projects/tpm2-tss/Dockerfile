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
  apt-get install -y \
    autoconf \
    autoconf-archive \
    automake \
    build-essential \
    doxygen \
    g++ \
    gcc \
    git \
    gnulib \
    libssl-dev \
    libtool \
    m4 \
    net-tools \
    pkg-config \
    wget \
    libcmocka0 \
    libcmocka-dev \
    libgcrypt20-dev \
    libtool \
    liburiparser-dev \
    uthash-dev

# OpenSSL
ARG openssl_name=openssl-1.1.0h
WORKDIR /tmp
RUN wget --quiet --show-progress --progress=dot:giga https://www.openssl.org/source/$openssl_name.tar.gz \
	&& tar xvf $openssl_name.tar.gz \
	&& rm /tmp/$openssl_name.tar.gz
WORKDIR $openssl_name
RUN ./config --prefix=/usr/local/openssl --openssldir=/usr/local/openssl \
	&& make -j$(nproc) \
	&& make install \
	&& openssl version

# IBM's Software TPM 2.0
ARG ibmtpm_name=ibmtpm1119
WORKDIR /tmp
RUN wget --quiet --show-progress --progress=dot:giga "https://downloads.sourceforge.net/project/ibmswtpm2/$ibmtpm_name.tar.gz" \
	&& sha256sum $ibmtpm_name.tar.gz | grep ^b9eef79904e276aeaed2a6b9e4021442ef4d7dfae4adde2473bef1a6a4cd10fb \
	&& mkdir -p $ibmtpm_name \
	&& tar xvf $ibmtpm_name.tar.gz -C $ibmtpm_name \
	&& rm $ibmtpm_name.tar.gz
WORKDIR $ibmtpm_name/src
RUN CFLAGS="-I/usr/local/openssl/include" make -j$(nproc) \
	&& cp tpm_server /usr/local/bin

RUN git clone --depth 1 \
  https://github.com/tpm2-software/tpm2-tss $SRC/tpm2-tss/
WORKDIR $SRC/tpm2-tss/
COPY build.sh $SRC/
