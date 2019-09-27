# Copyright 2019 Google Inc.
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
MAINTAINER bshas3@gmail.com
RUN apt-get update && apt-get install -y make autoconf automake libtool \
    flex bison build-essential \
    autopoint pkg-config gettext libffi-dev liblzma-dev \
    libvorbis-dev libtheora-dev libogg-dev zlib1g-dev cmake
RUN git clone --depth 1 -b ossfuzz https://github.com/bshastry/wds.git wds

# Install static glib
ADD https://ftp.gnome.org/pub/gnome/sources/glib/2.54/glib-2.54.2.tar.xz $SRC 
RUN tar xvJf $SRC/glib-2.54.2.tar.xz -C /usr/src; \
  cd /usr/src/glib-2.54.2; \
  ./configure --prefix=/usr --enable-static --disable-shared --disable-libmount --with-pcre=internal; \
  make -j; \
  make install; \
  rm -rf /usr/src/glib-2.54.2;

# Install static gstreamer lib
RUN git clone --depth 1 --recursive https://anongit.freedesktop.org/git/gstreamer/gstreamer /usr/src/gstreamer; \
  mkdir -p build-gstreamer; \
  cd build-gstreamer; \
  /usr/src/gstreamer/autogen.sh --prefix=/usr --disable-shared --enable-static --disable-examples --disable-gtk-doc --disable-introspection --enable-static-plugins --disable-gst-tracer-hooks --disable-registry; \
  make -j; \
  make install; \
  rm -rf /usr/src/gstreamer; 
WORKDIR wds
COPY build.sh $SRC/
