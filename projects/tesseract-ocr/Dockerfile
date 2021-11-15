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
RUN apt-get update && apt-get install -y autoconf automake libtool pkg-config libpng-dev libjpeg8-dev liblzma-dev

RUN git clone https://www.cl.cam.ac.uk/~mgk25/git/jbigkit jbigkit && \
    cd jbigkit && \
    make clean && \
    make -j$(nproc) lib && \
    cp libjbig/libjbig.a /usr/lib/x86_64-linux-gnu/libjbig.a

RUN git clone --depth 1 https://gitlab.com/libtiff/libtiff libtiff && \
  cd libtiff && \
  cmake . -DBUILD_SHARED_LIBS=off && \
  make clean && \
  make -j$(nproc) && \
  make install && \
  cp libtiff/libtiff.a /usr/lib/x86_64-linux-gnu/libtiff.a

RUN git clone --depth 1 https://github.com/danbloomberg/leptonica
RUN git clone --depth 1 https://github.com/tesseract-ocr/tesseract
RUN git clone --depth 1 https://github.com/tesseract-ocr/tessdata

COPY build.sh $SRC/
