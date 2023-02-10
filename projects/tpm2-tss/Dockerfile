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
    autoconf-archive \
    curl \
    libcmocka0 \
    libcmocka-dev \
    net-tools \
    build-essential \
    git \
    pkg-config \
    gcc \
    g++ \
    m4 \
    libtool \
    automake \
    libgcrypt20-dev \
    libssl-dev \
    autoconf \
    gnulib \
    wget \
    doxygen \
    libdbus-1-dev \
    libglib2.0-dev \
    clang-6.0 \
    clang-tools-6.0 \
    pandoc \
    lcov \
    libcurl4-openssl-dev \
    dbus-x11 \
    python-yaml \
    python3-yaml \
    vim-common \
    acl

RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-6.0 100
RUN update-alternatives --install /usr/bin/scan-build scan-build /usr/bin/scan-build-6.0 100

ARG autoconf_archive=autoconf-archive-2018.03.13
WORKDIR /tmp 
RUN wget --quiet --show-progress --progress=dot:giga "http://mirror.kumi.systems/gnu/autoconf-archive/$autoconf_archive.tar.xz" \
		&& tar -xf $autoconf_archive.tar.xz \
        && rm $autoconf_archive.tar.xz \
        && cd $autoconf_archive \
        && ./configure --prefix=/usr \
        && make -j $(nproc) && make install
RUN rm -fr $autoconf_archive.tar.xz

ARG ibmtpm_name=ibmtpm1661
WORKDIR /tmp
RUN wget --quiet --show-progress --progress=dot:giga "https://downloads.sourceforge.net/project/ibmswtpm2/$ibmtpm_name.tar.gz" \
	&& sha256sum $ibmtpm_name.tar.gz | grep ^55145928ad2b24f34be6a0eacf9fb492e10e0ea919b8428c721fa970e85d6147 \
	&& mkdir -p $ibmtpm_name \
	&& tar xvf $ibmtpm_name.tar.gz -C $ibmtpm_name \
	&& rm $ibmtpm_name.tar.gz
WORKDIR $ibmtpm_name/src
RUN CFLAGS="-I/usr/local/openssl/include" make -j$(nproc) \
&& cp tpm_server /usr/local/bin
RUN rm -fr $ibmtpm_name/src $ibmtpm_name.tar.gz

ARG uthash="2.1.0"
WORKDIR /tmp
RUN wget --quiet --show-progress --progress=dot:giga "https://github.com/troydhanson/uthash/archive/v${uthash}.tar.gz" \
	&& tar -xf v${uthash}.tar.gz \
        && cp uthash-${uthash}/src/*.h /usr/include/
RUN rm -rf uthash-${uthash}/ v${uthash}.tar.gz

RUN git clone --depth 1 \
  https://github.com/tpm2-software/tpm2-tss $SRC/tpm2-tss/
WORKDIR $SRC/tpm2-tss/
COPY build.sh $SRC/
