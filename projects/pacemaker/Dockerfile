# Copyright 2024 Google LLC
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
RUN apt-get update && apt-get install -y make autoconf automake libtool \
  pkg-config cmake nasm autopoint gettext python3 libqb-dev libbz2-dev \
  libglib2.0-dev corosync libgnutls28-dev libcfg-dev libcpg-dev libcmap-dev \
  libquorum-dev libpython3-dev libdbus-1-dev

RUN wget https://github.com/unicode-org/icu/releases/download/release-66-1/icu4c-66_1-src.tgz && tar xzvf icu4c-66_1-src.tgz
RUN cd $SRC/icu/source && \
   ./configure --disable-shared --enable-static --disable-layoutex \
  --disable-tests --disable-samples --with-data-packaging=static && \
  make install -j4

# Build requires automake 1.16.3
RUN curl -LO http://mirrors.kernel.org/ubuntu/pool/main/a/automake-1.16/automake_1.16.5-1.3_all.deb && \
    apt install ./automake_1.16.5-1.3_all.deb

RUN git clone --depth 1 https://gitlab.gnome.org/GNOME/libxml2.git
RUN git clone --depth 1 https://gitlab.gnome.org/GNOME/libxslt.git


RUN cd $SRC/libxml2 && \
  ./autogen.sh \
    --without-legacy \
    --without-push \
    --without-python \
    --without-zlib \
    --without-lzma \
    --enable-static && \
  make -j$(nproc) all && \
  make install

RUN cd $SRC/libxslt && \
  cd $SRC/libxslt && \
  ./autogen.sh \
    --with-libxml-src=../libxml2 \
    --without-python \
    --without-debug \
    --without-debugger \
    --without-profiler \
    --enable-static && \
  make -j$(nproc) && \
  make install 

RUN git clone https://github.com/ClusterLabs/libqb && cd libqb && \
    ./autogen.sh && ./configure && make && make install

# Uncomment before merging
RUN git clone --depth 1 https://github.com/ClusterLabs/pacemaker

WORKDIR pacemaker
COPY build.sh $SRC/
