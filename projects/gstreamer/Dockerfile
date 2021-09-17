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
   pip3 install meson==0.55.1

# We must install libvorbis from scratch as otherwise we will run into
# undefined functions in Ubuntu 20.04
RUN git clone --depth 1 https://gitlab.xiph.org/xiph/vorbis.git && \
    cd $SRC/vorbis && \
    ./autogen.sh && \
    ./configure --enable-static && \
    make clean && \
    make -j$(nproc) && \
    make install

ADD https://ftp.gnome.org/pub/gnome/sources/glib/2.64/glib-2.64.2.tar.xz $SRC

# Checkout all development repositories
#RUN for i in orc  gstreamer gst-plugins-base gst-plugins-good gst-plugins-bad gst-plugins-ugly gst-libav; do git clone --depth 1 --recursive https://anongit.freedesktop.org/git/gstreamer/$i $i; done  
RUN \
  git clone --depth 1 --recursive https://gitlab.freedesktop.org/gstreamer/gstreamer.git gstreamer && \
  git clone --depth 1 --recursive https://gitlab.freedesktop.org/gstreamer/gst-plugins-base.git gst-plugins-base && \
  git clone --depth 1 --recursive https://gitlab.freedesktop.org/gstreamer/gst-ci.git gst-ci

RUN sed -i 's/theoraenc theoradec theora/theoraenc theoradec theora cairo/g' $SRC/gst-ci/fuzzing/build-oss-fuzz.sh

ADD https://people.freedesktop.org/~bilboed/gst-discoverer_seed_corpus.zip $SRC

WORKDIR gstreamer
COPY build.sh $SRC/
