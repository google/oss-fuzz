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
RUN apt-get update && apt-get install -y \
	autoconf autoconf-archive \
	automake \
	gengetopt \
	gtk-doc-tools \
	libconfig-dev \
	libglib2.0-dev \
	libgnutls28-dev \
	libini-config-dev \
	libjansson-dev \
	libnice-dev \
	libssl-dev \
	libtool \
	openssl \
	pkg-config

# install libsrtp dep from source
RUN git clone --single-branch --branch 2_2_x_throttle https://github.com/cisco/libsrtp.git libsrtp
RUN cd libsrtp && ./configure --enable-openssl && make -j$(nproc) shared_library && make install

# fetch Janus code
RUN git clone --single-branch --branch master https://github.com/meetecho/janus-gateway.git janus-gateway

WORKDIR $SRC
COPY build.sh $SRC/
