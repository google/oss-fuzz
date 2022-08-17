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
 gettext \
 autogen \
 autopoint \
 autoconf \
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
 python \
 rsync \
 gtk-doc-tools \
 libtasn1-bin

ENV GNULIB_TOOL $SRC/gnulib/gnulib-tool
RUN git clone git://git.savannah.gnu.org/gnulib.git
RUN git clone --depth=1 --recursive https://git.savannah.gnu.org/git/libunistring.git
RUN git clone --depth=1 https://gitlab.com/libidn/libidn2.git
RUN git clone --depth=1 --recursive https://github.com/rockdaboot/libpsl.git
RUN git clone --depth=1 https://git.lysator.liu.se/nettle/nettle.git
RUN git clone --depth=1 https://gitlab.com/gnutls/gnutls.git

RUN git clone https://git.savannah.gnu.org/git/wget.git

WORKDIR wget
COPY build.sh $SRC/
