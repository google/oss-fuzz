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
MAINTAINER dtardon@redhat.com
# install build requirements
RUN apt-get update
RUN apt-get build-dep -y \
    libmspub librevenge libcdr libvisio libpagemaker libfreehand libwpd \
    libwpg libwps libmwaw libe-book libabw
RUN apt-get install -y liblzma-dev libpng-dev wget liblangtag-dev
ADD https://dev-www.libreoffice.org/src/lcms2-2.8.tar.gz $SRC/
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
    $SRC/
RUN wget \
    https://sourceforge.net/projects/libwpd/files/corpus/wpdfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libwpg/files/corpus/wpgfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libwps/files/corpus/wpsfuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libmwaw/files/corpus/actafuzzer_seed_corpus.zip \
    https://sourceforge.net/projects/libebook/files/corpus/lrffuzzer_seed_corpus.zip \
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
WORKDIR $SRC
COPY build.sh abw.dict *.options $SRC/
