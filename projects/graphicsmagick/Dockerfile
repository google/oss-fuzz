# Copyright 2018 Google Inc.
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

# Needed tools
RUN apt-get update && \
    apt-get install -y \
    mercurial \
    automake \
    autopoint \
    cmake \
    libtool \
    nasm \
    pkg-config \
    po4a \
    ninja-build \
    libgflags-dev \
    yasm

# GraphicsMagick
RUN hg clone --time -b default https://foss.heptapod.net/graphicsmagick/graphicsmagick graphicsmagick || \
    hg clone --time -b default https://foss.heptapod.net/graphicsmagick/graphicsmagick graphicsmagick || \
    hg clone --time -b default https://foss.heptapod.net/graphicsmagick/graphicsmagick graphicsmagick

# Libtiff
RUN git clone --depth 1 https://gitlab.com/libtiff/libtiff

# h.265 codec implementation needed by libheif
RUN git clone --depth 1 https://github.com/strukturag/libde265 || \
    printf "https://github.com/strukturag/libde265 is not available!\n"

# x265 HEVC Encoder needed by libheif
# https://bitbucket.org/multicoreware/x265_git/src/stable/
# https://bitbucket.org/multicoreware/x265_git/src/master/
RUN git clone --depth 1 https://bitbucket.org/multicoreware/x265_git/src/stable/ x265 || \
    printf "https://bitbucket.org/multicoreware/x265_git/src/stable/ is not available!\n"

# AV1 Codec Library needed by libheif
RUN git clone --depth 1 --branch master https://aomedia.googlesource.com/aom aom || \
    printf "https://aomedia.googlesource.com/aom is not available!\n"

# AVC (OpenH264) Codec Library needed by libheif
RUN git clone --depth 1 https://github.com/cisco/openh264 openh264

# JPEG 2000 (OpenJPEG) Library needed by libheif
RUN git clone --depth 1 https://github.com/uclouvain/openjpeg openjpeg

# Libheif
RUN git clone --depth 1 https://github.com/strukturag/libheif

# WebP
RUN git clone --depth 1 https://github.com/webmproject/libwebp

# Zlib
RUN git clone --depth 1 https://github.com/madler/zlib

# XZ
RUN git clone --depth 1 https://github.com/tukaani-project/xz

# Zstd
RUN git clone --depth 1 https://github.com/facebook/zstd

# libjpeg-turbo
RUN git clone --depth 1 https://github.com/libjpeg-turbo/libjpeg-turbo

# Freetype
RUN git clone --depth 1 https://github.com/freetype/freetype

# Libpng
RUN git clone --depth 1 https://github.com/pnggroup/libpng

# Little-CMS
RUN git clone --depth 1 https://github.com/mm2/Little-CMS

# Bzip2
RUN git clone --depth 1 https://gitlab.com/federicomenaquintero/bzip2.git

# Jasper
RUN git clone --depth 1 https://github.com/jasper-software/jasper

# Libxml2 (fall back to github mirror if gitlab.gnome.org is overloaded)
RUN git clone --depth 1 https://gitlab.gnome.org/GNOME/libxml2.git || \
    git clone --depth 1 https://gitlab.gnome.org/GNOME/libxml2.git || \
    git clone --depth 1 https://github.com/GNOME/libxml2

# Libjxl
RUN git clone --depth 1 https://github.com/libjxl/libjxl.git

# Libzip
RUN git clone --depth 1 https://github.com/nih-at/libzip.git

# Libjxl sub-repositories
# Borrowed from projects/libjxl/Dockerfile
RUN git -C libjxl submodule update --init --recommend-shallow \
  third_party/brotli \
  third_party/highway \
  third_party/libjpeg-turbo \
  third_party/skcms

# JBIG-kit
RUN git clone https://www.cl.cam.ac.uk/~mgk25/git/jbigkit # does not support shallow

# Build!
WORKDIR $SRC/graphicsmagick
COPY build.sh $SRC/
