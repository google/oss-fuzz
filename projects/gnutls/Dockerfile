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

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y \
 make \
 pkg-config \
 autoconf \
 automake \
 autogen \
 autopoint \
 libtool \
 gperf \
 bison \
 texinfo \
 curl \
 gettext \
 gengetopt \
 wget \
 python \
 mercurial \
 gtk-doc-tools \
 libtasn1-bin \
 lzip

ENV GNULIB_TOOL $SRC/gnulib/gnulib-tool
RUN git clone --depth=500 git://git.savannah.gnu.org/gnulib.git
RUN wget -qO- https://ftp.gnu.org/gnu/libunistring/libunistring-latest.tar.gz | tar xz && mv libunistring-* libunistring
RUN wget -qO- https://ftp.gnu.org/gnu/libidn/libidn2-latest.tar.gz | tar xz && mv libidn2-* libidn2
RUN wget -qO- https://ftp.gnu.org/gnu/gmp/gmp-6.3.0.tar.gz | tar xz && mv gmp-* gmp
RUN wget -qO- https://ftp.gnu.org/gnu/libtasn1/libtasn1-4.20.0.tar.gz | tar xz && mv libtasn1-* libtasn1
RUN git clone --depth=1 https://git.lysator.liu.se/nettle/nettle.git --branch=nettle_3.10.1_release_20241230

# Try twice in case of network issues.
RUN git clone --depth=1 --recursive https://gitlab.com/gnutls/gnutls.git || git clone --depth=1 --recursive https://gitlab.com/gnutls/gnutls.git

WORKDIR gnutls
COPY build.sh $SRC/
