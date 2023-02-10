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

RUN apt-get update && apt-get install -y make autoconf libtool pkg-config \
        libbz2-dev liblzo2-dev liblzma-dev liblz4-dev libz-dev \
        libssl-dev libacl1-dev libattr1-dev lrzip liblzo2-dev \
	      liblz4-tool lzop zstd lcab genisoimage jlha-utils rar default-jdk sharutils
RUN curl -LO http://mirrors.kernel.org/ubuntu/pool/main/a/automake-1.16/automake_1.16.5-1.3_all.deb && \
    apt install ./automake_1.16.5-1.3_all.deb
RUN git clone --depth 1 https://github.com/libarchive/libarchive.git
RUN git clone --depth 1 https://gitlab.gnome.org/GNOME/libxml2.git
# compile libxml2 from source so we can statically link
RUN mkdir /deps && \
  cd $SRC/libxml2 && \
  ./autogen.sh \
      --without-debug \
      --without-ftp \
      --without-http \
      --without-legacy \
      --without-python \
      --enable-static && \
  make -j$(nproc) && \
  make install && \
  cp .libs/libxml2.a /deps/

COPY build.sh libarchive_fuzzer.cc $SRC/
WORKDIR $SRC
