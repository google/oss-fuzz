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
# install build requirements
RUN apt-get update && \
    apt-get install -y wget xz-utils autoconf automake libtool pkg-config \
        gperf libglm-dev patch
ADD https://dev-www.libreoffice.org/src/lcms2-2.8.tar.gz \
    https://dev-www.libreoffice.org/src/zlib-1.2.11.tar.xz \
    https://dev-www.libreoffice.org/src/libpng-1.6.34.tar.xz \
    https://dev-www.libreoffice.org/src/libxml2-2.9.7.tar.gz \
    https://dev-www.libreoffice.org/src/icu4c-60_2-src.tgz \
    https://dev-www.libreoffice.org/src/mdds-1.3.1.tar.bz2 \
    https://dev-www.libreoffice.org/src/boost_1_66_0.tar.bz2 \
    $SRC/
# download fuzzing corpora
ADD https://dev-www.libreoffice.org/corpus/olefuzzer_seed_corpus.zip \
    https://dev-www.libreoffice.org/corpus/pubfuzzer_seed_corpus.zip \
    https://dev-www.libreoffice.org/corpus/zipfuzzer_seed_corpus.zip \
    https://dev-www.libreoffice.org/corpus/cdrfuzzer_seed_corpus.zip \
    https://dev-www.libreoffice.org/corpus/vsdfuzzer_seed_corpus.zip \
    https://dev-www.libreoffice.org/corpus/zmffuzzer_seed_corpus.zip \
    https://dev-www.libreoffice.org/corpus/pmdfuzzer_seed_corpus.zip \
    https://dev-www.libreoffice.org/corpus/fhfuzzer_seed_corpus.zip \
    https://dev-www.libreoffice.org/corpus/cmxfuzzer_seed_corpus.zip \
    https://dev-www.libreoffice.org/corpus/sdcfuzzer_seed_corpus.zip \
    https://dev-www.libreoffice.org/corpus/bmifuzzer_seed_corpus.zip \
    https://dev-www.libreoffice.org/corpus/abwfuzzer_seed_corpus.zip \
    https://dev-www.libreoffice.org/corpus/sdafuzzer_seed_corpus.zip \
    https://dev-www.libreoffice.org/corpus/sddfuzzer_seed_corpus.zip \
    https://dev-www.libreoffice.org/corpus/sdwfuzzer_seed_corpus.zip \
    https://dev-www.libreoffice.org/corpus/key6fuzzer_seed_corpus.zip \
    https://dev-www.libreoffice.org/corpus/vsdxfuzzer_seed_corpus.zip \
    https://dev-www.libreoffice.org/corpus/vdxfuzzer_seed_corpus.zip \
    https://dev-www.libreoffice.org/corpus/qxpfuzzer_seed_corpus.zip \
    $SRC/
RUN wget -q --show-progress --progress=bar:force \
    https://sourceforge.net/projects/libwpd/files/corpus/wpdfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libwpg/files/corpus/wpgfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libwps/files/corpus/wpsfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/actafuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libebook/files/corpus/lrffuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libwps/files/corpus/wksfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libwps/files/corpus/wdbfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libwps/files/corpus/docfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libwps/files/corpus/wrifuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/powerpointfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/mswrdfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/mswksfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libwps/files/corpus/123fuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libwps/files/corpus/wqfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libebook/files/corpus/pdbfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/beaglewksfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/clariswksfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/greatwksfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/applepictfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/clarisdrawfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/cricketdrawfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/freehandfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/macdraftfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/macdrawfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/macpaintfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/pixelpaintfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/superpaintfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/wingzfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/docmkrfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/edocfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/fullwrtfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/hanmacwrdfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/lightwaytxtfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/macdocfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/macwrtfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/marinerwrtfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/maxwrtfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/mindwrtfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/morefuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/mousewrtfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/nisuswrtfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/ragtimefuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/stylefuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/teachtxtfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/writenowfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/writerplsfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/zwrtfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/multiplanfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libwps/files/corpus/mpfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libebook/files/corpus/fb2fuzzer_seed_corpus.zip \
    -P $SRC
# clone sources
RUN git clone --depth 1 git://git.code.sf.net/p/libwpd/librevenge
RUN git clone --depth 1 git://gerrit.libreoffice.org/libmspub
RUN git clone --depth 1 git://gerrit.libreoffice.org/libcdr
RUN git clone --depth 1 git://gerrit.libreoffice.org/libvisio
RUN git clone --depth 1 git://gerrit.libreoffice.org/libzmf
RUN git clone --depth 1 git://gerrit.libreoffice.org/libpagemaker
RUN git clone --depth 1 git://gerrit.libreoffice.org/libfreehand
RUN git clone --depth 1 git://git.code.sf.net/p/libwpd/code libwpd
RUN git clone --depth 1 git://git.code.sf.net/p/libwpg/code libwpg
RUN git clone --depth 1 https://github.com/fosnola/libstaroffice
RUN git clone --depth 1 git://git.code.sf.net/p/libwps/code libwps
RUN git clone --depth 1 git://git.code.sf.net/p/libmwaw/libmwaw
RUN git clone --depth 1 git://git.code.sf.net/p/libebook/code libe-book
RUN git clone --depth 1 git://gerrit.libreoffice.org/libabw
RUN git clone --depth 1 git://gerrit.libreoffice.org/libetonyek
RUN git clone --depth 1 git://gerrit.libreoffice.org/libqxp
WORKDIR $SRC
COPY build.sh *.options *.patch $SRC/
