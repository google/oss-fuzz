# Copyright 2021 Google Inc.
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
RUN apt-get install -y pkg-config liblzma-dev libbz2-dev libjpeg-turbo8-dev \
                       libjpeg8-dev libtheora-dev libass-dev libx264-dev    \
                       libvorbis-dev libjansson-dev libxml2-dev libvpx-dev  \
                       libspeex-dev libopus-dev libnuma-dev libtool-bin wget
RUN pip3 install meson

RUN wget http://www.nasm.us/pub/nasm/releasebuilds/2.14.02/nasm-2.14.02.tar.bz2 && \
    tar xfj nasm-2.14.02.tar.bz2 && \
    cd nasm-2.14.02/ && \
    ./autogen.sh && \
    ./configure --prefix=/usr/local/ && \
    make && \
    make install

RUN wget https://github.com/ninja-build/ninja/releases/download/v1.8.2/ninja-linux.zip && \
     unzip ninja-linux.zip -d /usr/local/bin/ && \
     update-alternatives --install /usr/bin/ninja ninja /usr/local/bin/ninja 1 --force

RUN wget https://sourceforge.net/projects/lame/files/lame/3.99/lame-3.99.5.tar.gz/download  && \
       mv download lame-3.99.5.tar.gz && \
       tar -zxvf lame-3.99.5.tar.gz && \
       cd lame-3.99.5 && \
       ./configure && \
       make && make install

RUN git clone --depth 1 https://github.com/HandBrake/HandBrake handbrake
WORKDIR handbrake
COPY build.sh $SRC/
COPY fuzz_hb.c $SRC/fuzz_hb.c
