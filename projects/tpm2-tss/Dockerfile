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
FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04

ENV DEBIAN_FRONTEND=noninteractive
ENV PIP_REQUIRE_VIRTUALENV=0
ENV PIP_BREAK_SYSTEM_PACKAGES=1
RUN apt-get update && \
    apt-get install -y \
    acl \
    autoconf \
    autoconf-archive \
    automake \
    bear \
    build-essential \
    clang \
    clang-format \
    clang-tidy \
    clang-tools \
    curl \
    dbus-x11 \
    default-jdk \
    default-jre \
    doxygen \
    expect \
    g++ \
    gawk \
    gcc \
    git \
    gnulib \
    gnutls-bin \
    iproute2 \
    lcov \
    libcmocka-dev \
    libcmocka0 \
    libcurl4-openssl-dev \
    libdbus-1-dev \
    libengine-pkcs11-openssl \
    libftdi-dev \
    libgcrypt20-dev \
    libglib2.0-dev \
    libgmp-dev \
    libjson-c-dev \
    libjson-glib-dev \
    libmbedtls-dev \
    libnss3-tools \
    libseccomp-dev \
    libsqlite3-dev \
    libssl-dev \
    libtasn1-6-dev \
    libtool \
    libusb-1.0-0-dev \
    libyaml-dev \
    m4 \
    net-tools \
    opensc \
    pandoc \
    pkg-config \
    python3 \
    python3-pip \
    rustc \
    socat \
    sqlite3 \
    uthash-dev \
    uuid-dev \
    vim-common \
    wget \
    && rm -rf /var/lib/apt/lists/*

ARG ibmtpm_name=ibmtpm1682
RUN cd /tmp \
	&& wget $WGET_EXTRA_FLAGS "https://downloads.sourceforge.net/project/ibmswtpm2/$ibmtpm_name.tar.gz" \
	&& sha1sum $ibmtpm_name.tar.gz | grep ^651800d0b87cfad55b004fbdace4e41dce800a61 \
	&& mkdir -p $ibmtpm_name \
	&& (tar xv --no-same-owner -f $ibmtpm_name.tar.gz -C $ibmtpm_name \
		|| python3 -c 'import sys, tarfile; archive="/tmp/%s.tar.gz" % sys.argv[1]; dest="/tmp/%s" % sys.argv[1]; tarfile.open(archive, "r:gz").extractall(dest)' "$ibmtpm_name") \
	&& rm $ibmtpm_name.tar.gz \
	&& cd $ibmtpm_name/src \
	&& sed -i 's/0x300000ff/0x310000ff/' TpmToOsslMath.h \
	&& sed -i 's/-DTPM_NUVOTON/-DTPM_NUVOTON $(CFLAGS)/' makefile \
	&& CFLAGS="-DNV_MEMORY_SIZE=32768 -DMIN_EVICT_OBJECTS=7" make -j$(nproc) \
	&& cp tpm_server /usr/local/bin \
	&& strip /usr/local/bin/tpm_server || true \
	&& rm -fr /tmp/$ibmtpm_name

ARG libtpms_version=0.10.2
ARG swtpm_version=0.10.1
COPY libtpms.patch /tmp/libtpms.patch
RUN cd /tmp/ \
    && wget $WGET_EXTRA_FLAGS https://github.com/stefanberger/libtpms/archive/refs/tags/v$libtpms_version.tar.gz \
    && (tar xv --no-same-owner -f v$libtpms_version.tar.gz \
	|| python3 -c 'import sys, tarfile; archive="/tmp/v%s.tar.gz" % sys.argv[1]; dest="/tmp"; tarfile.open(archive, "r:gz").extractall(dest)' "$libtpms_version") \
	&& cd /tmp/libtpms-$libtpms_version \
	&& ./autogen.sh --prefix=/usr $LIBTPMS_AUTOGEN_EXTRA --with-openssl --with-tpm2 \
        && (command -d patch && patch -p1 < /tmp/libtpms.patch || true) \
	&& make -j$(nproc) \
	&& make install \
    && cd /tmp/ \
	&& rm -fr /tmp/libtpms-$libtpms_version \
    && rm -f /tmp/v$libtpms_version.tar.gz \
    && wget $WGET_EXTRA_FLAGS https://github.com/stefanberger/swtpm/archive/refs/tags/v$swtpm_version.tar.gz \
    && (tar xv --no-same-owner -f v$swtpm_version.tar.gz \
	|| python3 -c 'import sys, tarfile; archive="/tmp/v%s.tar.gz" % sys.argv[1]; dest="/tmp"; tarfile.open(archive, "r:gz").extractall(dest)' "$swtpm_version") \
	&& cd /tmp/swtpm-$swtpm_version \
	&& ./autogen.sh --prefix=/usr \
	&& make -j$(nproc) $SWTPM_MAKE_EXTRA \
	&& make install \
    && cd /tmp/ \
	&& rm -fr /tmp/swtpm-$swtpm_version \
    && rm -f /tmp/v$swtpm_version.tar.gz \
    && rm /tmp/libtpms.patch


WORKDIR /

ENV PIP_BREAK_SYSTEM_PACKAGES=1
RUN python3 -m pip install --no-cache-dir --break-system-packages \
    compiledb \
    && rm -rf /root/.cache/pip

RUN git clone --depth 1 \
	https://github.com/tpm2-software/tpm2-tss $SRC/tpm2-tss/
WORKDIR $SRC/tpm2-tss/
COPY *.sh $SRC/
