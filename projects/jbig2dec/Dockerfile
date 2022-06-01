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
RUN apt-get update && apt-get install -y make libtool pkg-config vim libreadline-dev wget autoconf
RUN git clone --recursive --depth 1 git://git.ghostscript.com/jbig2dec.git jbig2dec
RUN mkdir tests
RUN cp $SRC/jbig2dec/annex-h.jbig2 tests/annex-h.jb2
RUN cd tests && wget https://jbig2dec.com/tests/t89-halftone.zip && unzip t89-halftone.zip
RUN cd tests && wget https://jbig2dec.com/tests/jb2streams.zip && unzip jb2streams.zip
RUN cd tests && zip -q $SRC/jbig2_fuzzer_seed_corpus.zip *.jb2
RUN rm -rf tests
COPY *.dict $SRC/
WORKDIR jbig2dec
COPY *.cc $SRC/
COPY build.sh *.options $SRC/
