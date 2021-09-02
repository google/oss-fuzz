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

# Using Ubuntu 16.04 because of breakage on Ubuntu 20.04.
# See https://github.com/google/oss-fuzz/issues/6291 for more details.
FROM gcr.io/oss-fuzz-base/base-builder:xenial
# Delete line above and uncomment line below to upgrade to 20.04.
# FROM gcr.io/oss-fuzz-base/base-builder
# Install the build dependencies

# install the minimum

RUN sed -i '/^#\sdeb-src /s/^#//' "/etc/apt/sources.list" && \
   apt-get update && \
   apt-get install -y build-essential pkg-config bison flex gettext \
    libffi-dev liblzma-dev libvorbis-dev libtheora-dev libogg-dev zlib1g-dev \
    python3-pip && \
   pip3 install meson==0.55.1 ninja==1.10.0.post2

ADD https://ftp.gnome.org/pub/gnome/sources/glib/2.64/glib-2.64.2.tar.xz $SRC

# Checkout all development repositories
#RUN for i in orc  gstreamer gst-plugins-base gst-plugins-good gst-plugins-bad gst-plugins-ugly gst-libav; do git clone --depth 1 --recursive https://anongit.freedesktop.org/git/gstreamer/$i $i; done  
RUN \
  git clone --depth 1 --recursive https://gitlab.freedesktop.org/gstreamer/gstreamer.git gstreamer && \
  git clone --depth 1 --recursive https://gitlab.freedesktop.org/gstreamer/gst-plugins-base.git gst-plugins-base && \
  git clone --depth 1 --recursive https://gitlab.freedesktop.org/gstreamer/gst-ci.git gst-ci

ADD https://people.freedesktop.org/~bilboed/gst-discoverer_seed_corpus.zip $SRC

WORKDIR gstreamer
COPY build.sh $SRC/
