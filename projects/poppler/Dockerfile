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
MAINTAINER jonathan@titanous.com
RUN apt-get update && apt-get install -y make autoconf automake libtool pkg-config cmake
RUN git clone --depth 1 https://anongit.freedesktop.org/git/poppler/poppler.git
RUN git clone --depth 1 git://git.sv.nongnu.org/freetype/freetype2.git
RUN git clone --depth 1 https://github.com/mozilla/pdf.js pdf.js && \
    zip -q $SRC/pdf_fuzzer_seed_corpus.zip pdf.js/test/pdfs/*.pdf && \
    rm -rf pdf.js
ADD https://raw.githubusercontent.com/rc0r/afl-fuzz/master/dictionaries/pdf.dict $SRC/pdf_fuzzer.dict
WORKDIR $SRC/poppler
COPY *.cc $SRC/fuzz/
COPY build.sh $SRC/
