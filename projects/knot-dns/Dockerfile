# Copyright 2017 Google Inc.
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
 autoconf \
 autogen \
 automake \
 autopoint \
 bison \
 gettext \
 gperf \
 gtk-doc-tools \
 libev-dev \
 libev4 \
 libtasn1-bin \
 libtool \
 make \
 pkg-config \
 texinfo \
 wget

ENV GNULIB_TOOL $SRC/gnulib/gnulib-tool
RUN git clone git://git.savannah.gnu.org/gnulib.git
RUN git clone --depth=1 --recursive https://git.savannah.gnu.org/git/libunistring.git
RUN git clone --depth=1 https://git.lysator.liu.se/nettle/nettle.git
RUN git clone --depth=1 https://gitlab.com/gnutls/gnutls.git
RUN git clone --depth=1 https://github.com/LMDB/lmdb.git
RUN git clone --depth=1 https://gitlab.labs.nic.cz/knot/knot-dns

WORKDIR knot-dns
COPY build.sh $SRC/
