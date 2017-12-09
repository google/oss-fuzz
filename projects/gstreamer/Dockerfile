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
MAINTAINER bilboed@bilboed.com
# Install the build dependencies

# install the minimum

RUN sed -i '/^#\sdeb-src /s/^#//' "/etc/apt/sources.list" && \
   apt-get update && \
   apt-get install -y make autoconf automake libtool build-essential \
    autopoint pkg-config bison flex gettext libffi-dev liblzma-dev \
    libvorbis-dev libtheora-dev libogg-dev zlib1g-dev

ADD https://ftp.gnome.org/pub/gnome/sources/glib/2.54/glib-2.54.2.tar.xz $SRC

# Checkout all development repositories
#RUN for i in orc  gstreamer gst-plugins-base gst-plugins-good gst-plugins-bad gst-plugins-ugly gst-libav; do git clone --depth 1 --recursive https://anongit.freedesktop.org/git/gstreamer/$i $i; done  
RUN \
  git clone --depth 1 --recursive https://anongit.freedesktop.org/git/gstreamer/gstreamer gstreamer && \
  git clone --depth 1 --recursive https://anongit.freedesktop.org/git/gstreamer/gst-plugins-base gst-plugins-base && \
  git clone --depth 1 --recursive https://anongit.freedesktop.org/git/gstreamer/gst-ci gst-ci

ADD https://people.freedesktop.org/~bilboed/gst-discoverer_seed_corpus.zip $SRC

WORKDIR gstreamer
COPY build.sh $SRC/
