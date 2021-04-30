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
RUN apt-get update && apt-get install -y mercurial automake autopoint cmake libtool nasm pkg-config po4a
RUN hg clone --time -b default https://hg.osdn.net/view/graphicsmagick/GM graphicsmagick || \
    hg clone --time -b default https://hg.osdn.net/view/graphicsmagick/GM graphicsmagick || \
    hg clone --time -b default https://hg.osdn.net/view/graphicsmagick/GM graphicsmagick

RUN git clone --depth 1 https://gitlab.com/libtiff/libtiff
RUN git clone --depth 1 https://github.com/webmproject/libwebp
RUN git clone --depth 1 https://github.com/madler/zlib
RUN git clone --depth 1 https://github.com/xz-mirror/xz
RUN git clone --depth 1 https://github.com/facebook/zstd
RUN git clone --depth 1 https://github.com/libjpeg-turbo/libjpeg-turbo
RUN git clone https://git.savannah.nongnu.org/r/freetype/freetype2.git/
RUN git clone --depth 1 https://github.com/pnggroup/libpng
RUN git clone --depth 1 https://github.com/mm2/Little-CMS
RUN git clone http://git.ghostscript.com/ghostpdl.git
RUN git clone --depth 1 https://gitlab.com/federicomenaquintero/bzip2.git
RUN git clone --depth 1 https://github.com/jasper-software/jasper
RUN git clone --depth 1 https://gitlab.gnome.org/GNOME/libxml2.git

WORKDIR graphicsmagick
COPY build.sh $SRC/
