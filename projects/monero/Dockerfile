# Copyright 2020 The Monero Project
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

# Multistage docker build, requires docker 17.05

# builder stage
FROM gcr.io/oss-fuzz-base/base-builder

RUN set -ex && \
    apt-get update && \
    apt-get --no-install-recommends --yes install \
        ca-certificates \
        cmake \
        g++ \
        make \
        pkg-config \
        graphviz \
        doxygen \
        git \
        curl \
        libtool \
        libtool-bin \
        flex \
        bison \
        autoconf \
        automake \
        bzip2 \
        xsltproc \
        gperf \
        unzip \
        cmake \
        ccache \
        libsodium-dev \
        libreadline-dev \
        libudev-dev \
        libprotobuf-dev \
        protobuf-compiler \
        libexpat-dev

WORKDIR monero

ENV CFLAGS="${CFLAGS} -fPIC -pthread"
ENV CXXFLAGS="${CXXFLAGS} -fPIC -pthread"

## Boost
ARG BOOST_VERSION=1_70_0
ARG BOOST_VERSION_DOT=1.70.0
ARG BOOST_HASH=430ae8354789de4fd19ee52f3b1f739e1fba576f0aded0897c3c2bc00fb38778
RUN set -ex \
    && curl -s -L -o  boost_${BOOST_VERSION}.tar.bz2 https://downloads.getmonero.org/libs/boost_${BOOST_VERSION}.tar.bz2 \
    && echo "${BOOST_HASH}  boost_${BOOST_VERSION}.tar.bz2" | sha256sum -c \
    && tar -xjf boost_${BOOST_VERSION}.tar.bz2 \
    && cd boost_${BOOST_VERSION} \
    && sed -i -e 's/use(* m_instance)/if (m_instance) use(* m_instance)/' boost/serialization/singleton.hpp \
    && ./bootstrap.sh --with-toolset=clang \
    && ./b2 --build-type=minimal link=static runtime-link=static --with-chrono --with-date_time --with-filesystem --with-program_options --with-regex --with-serialization --with-system --with-thread --with-locale threading=multi threadapi=pthread cflags="$CFLAGS" cxxflags="$CXXFLAGS" stage
ENV BOOST_ROOT /usr/local/boost_${BOOST_VERSION}

# OpenSSL
ARG OPENSSL_VERSION=1.1.1g
ARG OPENSSL_HASH=ddb04774f1e32f0c49751e21b67216ac87852ceb056b75209af2443400636d46
RUN set -ex \
    && curl -s -O https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz \
    && echo "${OPENSSL_HASH}  openssl-${OPENSSL_VERSION}.tar.gz" | sha256sum -c \
    && tar -xzf openssl-${OPENSSL_VERSION}.tar.gz \
    && cd openssl-${OPENSSL_VERSION} \
    && ./Configure linux-x86_64 no-shared --static "$CFLAGS" \
    && make build_generated \
    && make libcrypto.a \
    && make install
ENV OPENSSL_ROOT_DIR=/usr/local/openssl-${OPENSSL_VERSION}

# ZMQ
ARG ZMQ_VERSION=v4.3.2
ARG ZMQ_HASH=a84ffa12b2eb3569ced199660bac5ad128bff1f0
RUN set -ex \
    && git clone --depth=1 https://github.com/zeromq/libzmq.git -b ${ZMQ_VERSION} \
    && cd libzmq \
    && test `git rev-parse HEAD` = ${ZMQ_HASH} || exit 1 \
    && sed -i -e 's/::~generic_mtrie_t /::~generic_mtrie_t<T> /' src/generic_mtrie_impl.hpp \
    && ./autogen.sh \
    && ./configure --enable-static --disable-shared --with-libsodium \
    && make \
    && make install \
    && ldconfig

# Libusb
ARG USB_VERSION=v1.0.22
ARG USB_HASH=0034b2afdcdb1614e78edaa2a9e22d5936aeae5d
RUN set -ex \
    && git clone --depth=1 https://github.com/libusb/libusb.git -b ${USB_VERSION} \
    && cd libusb \
    && test `git rev-parse HEAD` = ${USB_HASH} || exit 1 \
    && ./autogen.sh \
    && ./configure --disable-shared \
    && make \
    && make install

# Hidapi
ARG HIDAPI_VERSION=hidapi-0.8.0-rc1
ARG HIDAPI_HASH=40cf516139b5b61e30d9403a48db23d8f915f52c
RUN set -ex \
    && git clone --depth=1 https://github.com/signal11/hidapi -b ${HIDAPI_VERSION} \
    && cd hidapi \
    && test `git rev-parse HEAD` = ${HIDAPI_HASH} || exit 1 \
    && ./bootstrap \
    && ./configure --enable-static --disable-shared \
    && make \
    && make install

RUN git clone https://github.com/NLnetLabs/unbound && \
    cd unbound && ./configure && make && make install

RUN git clone --depth 1 https://github.com/monero-project/monero.git monero
COPY build.sh $SRC/
