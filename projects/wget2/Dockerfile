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
 autogen \
 autopoint \
 autoconf \
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
 python \
 lzip \
 rsync \
 libmicrohttpd-dev \
 gtk-doc-tools \
 libtasn1-bin \
 libz-dev

# Get a more recent version of gettext as the one in the package
# manager is too old for wget2.
RUN wget https://ftp.gnu.org/pub/gnu/gettext/gettext-0.22.2.tar.gz && \
    tar -xzf ./gettext-0.22.2.tar.gz && \
    cd gettext-0.22.2 && \
    ./configure && \
    make && \
    make install
ENV GNULIB_TOOL $SRC/gnulib/gnulib-tool
ENV GNULIB_SRCDIR $SRC/gnulib
RUN git clone git://git.savannah.gnu.org/gnulib.git
RUN wget -qO- https://ftp.gnu.org/gnu/libunistring/libunistring-latest.tar.gz | tar -xz && mv libunistring-* libunistring
RUN wget -qO- https://ftp.gnu.org/gnu/libidn/libidn2-latest.tar.gz | tar -xz && mv libidn2-* libidn2
RUN git clone --depth=1 --recursive https://github.com/rockdaboot/libpsl.git
RUN git clone --depth=1 https://git.lysator.liu.se/nettle/nettle.git
RUN git clone --depth=1 https://gitlab.com/gnutls/gnutls.git
RUN wget -O- https://ftp.gnu.org/pub/gnu/libmicrohttpd/libmicrohttpd-latest.tar.gz | tar xz

# Get a more recent version of automake as the one in the package
# manager is too old for wget2.
RUN curl -LO http://mirrors.kernel.org/ubuntu/pool/main/a/automake-1.16/automake_1.16.5-1.3_all.deb && \
    apt install ./automake_1.16.5-1.3_all.deb

RUN git clone --recursive https://gitlab.com/gnuwget/wget2.git

WORKDIR wget2
COPY build.sh $SRC/
