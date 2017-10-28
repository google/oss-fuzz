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
MAINTAINER inkscape-devel@lists.sf.net
RUN apt-get update -yqq && apt-get install -y -qq \
# Build Tools
  cmake \
  intltool \
  pkg-config \
  python-dev \
  libtool \
  ccache \
  clang \
# Libraries
  libart-2.0-dev \
  libaspell-dev \
  libboost-dev \
  libcdr-dev \
  libgc-dev \
  libgdl-3-dev \
  libglib2.0-dev \
  libgnomevfs2-dev \
  libgsl-dev \
  libgtk-3-dev \
  libgtkmm-3.0-dev \
  libgtkspell-dev \
  libjemalloc-dev \
  liblcms2-dev \
  libmagick++-dev \
  libpango1.0-dev \
  libpng12-dev \
  libpoppler-glib-dev \
  libpoppler-private-dev \
  libpopt-dev \
  libpotrace-dev \
  librevenge-dev \
  libsigc++-2.0-dev \
  libsoup2.4-dev \
  libvisio-dev \
  libwpg-dev \
  libxml-parser-perl \
  libxml2-dev \
  libxslt1-dev \
  libyaml-dev \
  python-lxml \
  zlib1g-dev \
# Test Tools
  google-mock \
  imagemagick \
  libgtest-dev \
  fonts-dejavu \
&& rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://gitlab.com/inkscape/inkscape.git inkscape
WORKDIR inkscape
COPY build.sh $SRC/
