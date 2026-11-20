# Copyright 2016 Google Inc.
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
RUN apt-get update && apt-get install -y \
 make \
 pkg-config \
 gettext \
 autogen \
 autopoint \
 autoconf-archive \
 automake \
 libtool \
 texinfo \
 flex \
 bison \
 gettext \
 gengetopt \
 curl \
 gperf \
 wget \
 rsync \
 gtk-doc-tools \
 libtasn1-bin \
 libz-dev

RUN cd /usr/src && \
        curl -oautoconf-2.71.tar.gz https://ftp.gnu.org/gnu/autoconf/autoconf-2.71.tar.gz && \
	tar xf autoconf-2.71.tar.gz && \
	cd autoconf-2.71 && \
	./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var && \
	make install

ENV GNULIB_TOOL $SRC/gnulib/gnulib-tool
ENV GNULIB_SRCDIR $SRC/gnulib
RUN git clone https://git.savannah.gnu.org/git/gnulib.git gnulib
RUN wget -qO- https://ftp.gnu.org/gnu/libunistring/libunistring-latest.tar.gz | tar xz && mv libunistring-* libunistring
RUN wget -qO- https://ftp.gnu.org/gnu/libidn/libidn2-latest.tar.gz | tar xz && mv libidn2-* libidn2
RUN wget -qO- https://ftp.gnu.org/gnu/gmp/gmp-6.3.0.tar.gz | tar xz && mv gmp-* gmp
RUN git clone --depth=1 --recursive https://github.com/rockdaboot/libpsl.git
RUN git clone --depth=1 https://git.lysator.liu.se/nettle/nettle.git --branch=nettle_3.10_release_20240616
# gnutls dropped its bundled libtasn1 (the --with-included-libtasn1 configure
# option is gone), so it now needs libtasn1 >= 4.9 from outside. Build it from
# source into the same static dep prefix as everything else rather than relying
# on a distro package, so the static link keeps working.
RUN wget -qO- https://ftp.gnu.org/gnu/libtasn1/libtasn1-4.21.0.tar.gz | tar xz && mv libtasn1-* libtasn1
RUN git clone --depth=1 https://gitlab.com/gnutls/gnutls.git

RUN git clone https://git.savannah.gnu.org/git/wget.git

WORKDIR wget
COPY build.sh $SRC/
