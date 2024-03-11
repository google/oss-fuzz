# Copyright 2021 Google LLC
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

RUN sed -i -e 's/xenial/focal/g' /etc/apt/sources.list

RUN apt-get update -y && apt-get install -y --reinstall \
      automake \
      autoconf \
      autoconf-archive \
      build-essential \
      jq \
      libtool \
      make \
      pkg-config \
      wget

# Debug helpers.
RUN apt-get install -y \
      strace ltrace gdb vim

# `nix` requires `libeditline` to be >= 1.14;
# While latest version in Ubuntu repositories is 1.12 .
RUN git clone --branch 1.17.1 https://github.com/troglobit/editline.git \
      && cd editline \
      && ./autogen.sh \
      && ./configure \
      && make all \
      && make install \
      && cd - \
      && rm -R editline

# Install `libutil`'s dependencies.
RUN apt-get install -y \
      libarchive-dev \
      libboost-all-dev \
      libbrotli-dev \
      libcpuid-dev \
      libssl-dev
# `libutil`'s transitive dependencies.
RUN apt-get install -y \
      libacl1-dev \
      libbz2-dev \
      liblz4-dev \
      libxml2-dev \
      libzstd-dev

# `libutil` requires `libarchive`, that requires `liblzma`;
# Sadly, Ubuntu's `libzma.a` is missing some necessary definitions.
RUN wget https://tukaani.org/xz/xz-5.2.4.tar.gz \
      && tar xf xz-5.2.4.tar.gz \
      && cd xz-5.2.4 \
      && ./configure --enable-shared=no --enable-static \
      && make \
      && make install \
      && cd - \
      && rm -R xz-5.2.4*

# Install `libstore`'s dependencies.
RUN apt-get install -y \
      libsodium-dev \
      libsqlite3-dev
# `libstore`'s transitive dependencies.
RUN apt-get install -y \
      comerr-dev \
      libticonv-dev \
      libidn2-dev \
      libnghttp2-dev \
      libpsl-dev \
      libssh-dev \
      libunistring-dev \
      nettle-dev

# `libstore` requires `libcurl`;
# Sadly, `libcurl` requires `libkrb5`-related static libraries, which are not distributed anymore.
RUN wget https://curl.se/download/curl-7.68.0.tar.gz \
      && tar xf curl-7.68.0.tar.gz \
      && cd curl-7.68.0 \
      && ./configure --disable-shared --enable-static --disable-ldap --disable-sspi --with-openssl --without-librtmp --without-gnutls \
      && make \
      && make install \
      && cd - \
      && rm -R curl-7.68.0*

# Install other required dependencies./configure` fails.
RUN apt-get install -y \
      libgtest-dev \
      libseccomp-dev \
      libstdc++-10-dev

RUN apt autoremove -y \
      && rm -rf /var/lib/apt/lists/*

# Clone a fork to get the fuzz targets; Will eventually be PRed/merged upstream.
RUN git clone --depth 1 --branch fuzzing_meson https://github.com/Pamplemousse/nix.git

COPY build.sh $SRC/

# TODO: in the wait of having it integrated upstream.
COPY local.mk $SRC/nix/fuzz/
RUN echo "include fuzz/local.mk" >> $SRC/nix/Makefile
