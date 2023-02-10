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
RUN apt-get update && apt-get install -y wget autoconf automake libtool pkg-config gperf python
RUN pip3 install meson ninja gyp-next

RUN git clone --depth 1 https://github.com/madler/zlib.git
RUN git clone --depth 1 https://gitlab.freedesktop.org/freetype/freetype.git
RUN git clone --depth 1 https://github.com/mm2/Little-CMS.git
RUN git clone --depth 1 https://github.com/uclouvain/openjpeg
RUN git clone --depth 1 https://github.com/glennrp/libpng.git
RUN git clone --depth 1 https://gitlab.freedesktop.org/fontconfig/fontconfig.git
RUN git clone --depth 1 https://gitlab.freedesktop.org/cairo/cairo.git
RUN git clone --depth 1 --branch=5.15 git://code.qt.io/qt/qtbase.git
RUN git clone --depth 1 https://gitlab.gnome.org/GNOME/pango.git
ADD https://ftp.gnome.org/pub/gnome/sources/glib/2.70/glib-2.70.0.tar.xz $SRC
RUN tar xvJf $SRC/glib-2.70.0.tar.xz
RUN wget https://boostorg.jfrog.io/artifactory/main/release/1.76.0/source/boost_1_76_0.tar.bz2
RUN wget https://ftp.mozilla.org/pub/security/nss/releases/NSS_3_75_RTM/src/nss-3.75-with-nspr-4.32.tar.gz
RUN git clone --depth 1 --single-branch https://gitlab.freedesktop.org/poppler/poppler.git

RUN git clone --depth 1 https://github.com/mozilla/pdf.js pdf.js && \
    zip -q $SRC/poppler_seed_corpus.zip pdf.js/test/pdfs/*.pdf && \
    rm -rf pdf.js
ADD https://raw.githubusercontent.com/google/fuzzing/master/dictionaries/pdf.dict $SRC/poppler.dict
WORKDIR $SRC/poppler
COPY build.sh $SRC/
