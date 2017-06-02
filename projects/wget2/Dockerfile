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
MAINTAINER rockdaboot@gmail.com
RUN apt-get update && apt-get install -y \
 pkg-config \
 gettext \
 autopoint \
 autoconf \
 automake \
 libtool \
 texinfo \
 flex \
 liblzma-dev \
 libidn2-0-dev \
 libunistring-dev \
 zlib1g-dev \
 libbz2-dev \
 gnutls-dev \
 libpsl-dev \
 libnghttp2-dev \
 doxygen

RUN git clone --depth=1 https://gitlab.com/gnuwget/wget2.git
RUN cd wget2 && git submodule update --init

WORKDIR wget2
COPY build.sh $SRC/
