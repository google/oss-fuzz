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
RUN sed -i 's/# deb-src/deb-src/g' /etc/apt/sources.list
RUN apt-get update -yqq && apt-get install -y -qq \
# Build Tools
  cmake \
  intltool \
  pkg-config \
  python-dev \
  libtool \
  ccache \
  clang \
  wget \
  google-mock \
# Libraries
  libart-2.0-dev \
  libboost-dev \
  libgc-dev \
  #libgdl-3-dev \
  #libgnomevfs2-dev \
  libgsl-dev \
  #libgtk-3-dev \ #
  #libgtkmm-3.0-dev \ #
  libpango1.0-dev \
  libpng12-dev \
  libjpeg-dev \
  libtiff5-dev \
  #libpoppler-glib-dev \
  #libpoppler-private-dev \
  libpopt-dev \
  libsigc++-2.0-dev \
  libsoup2.4-dev \
  #libwpg-dev \
  libxml-parser-perl \
  libxml2-dev \
  libxslt1-dev \
  python-lxml \
  zlib1g-dev \
  #deps of built static ones
  libx11-dev \
  #libglib2.0-dev \
  #libcairomm-1.0-dev \
  libcairo2-dev \
  libcairomm-1.0-dev \
  libmount-dev \
  xorg-dev \
  libdbus-1-dev \
  gobject-introspection \
  mm-common \
  libepoxy-dev \
  libatspi2.0-dev 
  #libepoxy is a PITA, as well as libatspi
RUN git clone --depth 1 https://gitlab.com/inkscape/inkscape.git inkscape
RUN sed -i 's/SHARED/STATIC/g' inkscape/src/CMakeLists.txt
RUN apt-get source libgdk-pixbuf2.0-dev libglib2.0-dev libglibmm-2.4-dev libpangomm-1.4-dev libatk1.0-dev libatkmm-1.6-dev libgtk-3-dev libgtkmm-3.0-dev libepoxy-dev libatk-bridge2.0-dev libatspi2.0-dev libsigc++-2.0-dev libcairomm-1.0-dev libgdl-3-dev
RUN apt-get build-dep -yqq libgdk-pixbuf2.0-dev libglib2.0-dev libglibmm-2.4-dev libpangomm-1.4-dev libatk1.0-dev libatkmm-1.6-dev libgtk-3-dev libgtkmm-3.0-dev libepoxy-dev libatk-bridge2.0-dev libepoxy-dev libatspi2.0-dev libsigc++-2.0-dev libcairomm-1.0-dev libgdl-3-dev
RUN apt-get remove -yqq libgdk-pixbuf2.0-dev libglib2.0-dev libglibmm-2.4-dev libpangomm-1.4-dev libatk1.0-dev libatkmm-1.6-dev libgtk-3-dev libgtkmm-3.0-dev libepoxy-dev libatk-bridge2.0-dev libepoxy-dev libatspi2.0-dev libsigc++-2.0-dev libcairomm-1.0-dev libgdl-3-dev
# to debug stuff (+stuff that gets lost but has a .a available.)
RUN apt install -yqq libpango1.0-dev libcairo2-dev libsoup2.4-dev cmake-curses-gui locate vim bash-completion && updatedb
WORKDIR inkscape
COPY build.sh $SRC/
