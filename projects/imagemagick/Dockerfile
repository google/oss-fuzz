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
    apt-get install -y make autoconf automake groff libtool pkg-config cmake nasm autopoint
RUN git clone --depth 1 https://github.com/imagemagick/imagemagick
RUN git clone --depth 1 https://gitlab.com/libtiff/libtiff
RUN git clone --depth 1 https://github.com/strukturag/libde265
RUN git clone --depth 1 https://github.com/strukturag/libheif
RUN git clone --depth 1 https://github.com/uclouvain/openjpeg
RUN git clone --depth 1 https://github.com/webmproject/libwebp
RUN git clone --depth 1 https://github.com/madler/zlib
RUN git clone --depth 1 https://github.com/libjpeg-turbo/libjpeg-turbo
RUN git clone --depth 1 https://github.com/xz-mirror/xz
RUN git clone --depth 1 https://github.com/libraw/libraw
RUN git clone --depth 1 https://github.com/pnggroup/libpng
RUN git clone --depth 1 https://github.com/mm2/Little-CMS
RUN git clone --depth 1 https://github.com/freetype/freetype
RUN git clone --depth 1 https://gitlab.com/federicomenaquintero/bzip2.git
RUN git clone --depth 1 --recursive https://github.com/libjxl/libjxl
RUN git clone https://www.cl.cam.ac.uk/~mgk25/git/jbigkit # does not support shallow
RUN svn export https://github.com/mozillasecurity/fuzzdata.git/trunk/samples/heic heic_corpus
ADD https://lcamtuf.coredump.cx/afl/demo/afl_testcases.tgz afl_testcases.tgz
WORKDIR imagemagick
COPY build.sh $SRC/
