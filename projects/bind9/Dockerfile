# Copyright 2020 Google LLC
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
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get -y update && apt-get -y dist-upgrade
RUN apt-get -y install		\
	autoconf		\
	automake		\
	autotools-dev		\
	bison			\
	build-essential		\
	libcap-dev		\
	libnghttp2-dev		\
	libssl-dev		\
	libtool			\
	libtool-bin		\
	libuv1-dev		\
	pkg-config		\
	zip
RUN git clone --depth 1 https://gitlab.isc.org/isc-projects/bind9.git
WORKDIR bind9
COPY build.sh $SRC/
