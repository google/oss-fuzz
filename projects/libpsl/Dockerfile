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
 autoconf-archive \
 automake \
 libtool \
 texinfo \
 bison \
 gettext \
 gengetopt \
 curl \
 gperf \
 wget \
 python

RUN git clone git://git.savannah.gnu.org/gnulib.git
RUN git clone --depth=1 https://git.savannah.gnu.org/git/libunistring.git
RUN git clone --depth=1 https://gitlab.com/libidn/libidn2.git
RUN git clone --depth=1 https://git.savannah.gnu.org/git/libidn.git
RUN wget https://github.com/unicode-org/icu/releases/download/release-59-2/icu4c-59_2-src.tgz && tar xvfz icu4c-59_2-src.tgz

RUN git clone --depth=1 --recursive https://github.com/rockdaboot/libpsl.git

WORKDIR libpsl
COPY build.sh config.site md5sum $SRC/
