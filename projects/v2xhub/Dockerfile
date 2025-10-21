# Copyright 2025 Google LLC
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
RUN apt-get update && apt-get install -y make autoconf automake libtool
RUN git clone --depth 1 https://github.com/emptyiscolor/V2X-Hub v2xhub     # or use other version control
WORKDIR v2xhub

ENV DEBIAN_FRONTEND=noninteractive
ENV CC=gcc
ENV CXX=g++
ENV CFLAGS=
ENV CXXFLAGS=

RUN cp ./scripts/install_dependencies.sh /usr/local/bin/
RUN cp ./container/wait-for-it.sh /usr/local/bin/
RUN cp ./container/service.sh /usr/local/bin/
RUN mkdir -p /home/V2X-Hub
RUN /usr/local/bin/install_dependencies.sh
RUN cp -R ./container /home/V2X-Hub/container
RUN cp -R ./src /home/V2X-Hub/src/

# build out ext components
RUN cp -R ./ext /home/V2X-Hub/ext
WORKDIR /home/V2X-Hub/ext/
RUN ./build.sh


WORKDIR /home/V2X-Hub/container/
RUN ./database.sh
RUN ./library.sh
RUN ldconfig

RUN apt-get install -y software-properties-common gnupg ca-certificates &&\
	add-apt-repository -y ppa:ubuntu-toolchain-r/test &&\
	apt-get update -y &&\
	apt-get install -y gcc-11 g++-11 &&\
	update-alternatives --remove-all cpp &&\
	echo "[*] Registering GCC/G++ alternatives..." &&\
	update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-11 110 \
            --slave /usr/bin/g++ g++ /usr/bin/g++-11

RUN echo "[*] Setting GCC 11 as default..." &&\
	update-alternatives --set gcc /usr/bin/gcc-11 

ENV CC=gcc-11
ENV CXX=g++-11

# build specific librdkafka
RUN apt-get remove -y librdkafka-dev &&\
	cd /tmp/ &&\
	git clone https://github.com/confluentinc/librdkafka.git &&\
	cd librdkafka &&\
	git checkout v2.4.0 &&\
	./configure &&\
	make -j"$(nproc)" &&\
	make install &&\
	ldconfig 

ENV CC=clang CXX=clang++

# build internal components
WORKDIR /home/V2X-Hub/src/
COPY build.sh $SRC/
COPY StringParserSubstringFuzzer.cpp $SRC/
