# Copyright 2017 Google Inc.
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

RUN apt-get update && \
   apt-get install -y make autoconf automake libtool build-essential pkg-config bison flex gettext \
    libffi-dev liblzma-dev libtheora-dev libogg-dev zlib1g-dev libcairo2-dev \
    python3-pip ninja-build && \
   pip3 install meson==0.61.3

# We must install libvorbis from scratch as otherwise we will run into
# undefined functions in Ubuntu 20.04
RUN git clone --depth 1 https://gitlab.xiph.org/xiph/vorbis.git && \
    cd $SRC/vorbis && \
    ./autogen.sh && \
    ./configure --enable-static && \
    make clean && \
    make -j$(nproc) && \
    make install

ADD https://ftp.gnome.org/pub/gnome/sources/glib/2.72/glib-2.72.0.tar.xz $SRC

# Checkout repository
RUN git clone --depth 1 --recursive https://gitlab.freedesktop.org/gstreamer/gstreamer.git gstreamer

ADD https://people.freedesktop.org/~bilboed/gst-discoverer_seed_corpus.zip $SRC

WORKDIR gstreamer
COPY build.sh $SRC/
