# Copyright 2016 Google Inc.
# Copyright 2022 D. R. Commander
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
RUN apt-get update && apt-get install -y make yasm cmake
RUN git clone --depth 1 https://github.com/libjpeg-turbo/libjpeg-turbo libjpeg-turbo.main
RUN git clone --depth 1 https://github.com/libjpeg-turbo/libjpeg-turbo -b 2.0.x libjpeg-turbo.2.0.x
RUN git clone --depth 1 https://github.com/libjpeg-turbo/libjpeg-turbo -b dev libjpeg-turbo.dev || /bin/true

RUN git clone --depth 1 https://github.com/libjpeg-turbo/seed-corpora
RUN cd seed-corpora && zip -r ../decompress_fuzzer_seed_corpus.zip afl-testcases/jpeg* bugs/decompress* $SRC/libjpeg-turbo/testimages/*.jpg
RUN cd seed-corpora && zip -r ../compress_fuzzer_seed_corpus.zip afl-testcases/bmp afl-testcases/gif* bugs/compress* $SRC/libjpeg-turbo/testimages/*.bmp $SRC/libjpeg-turbo/testimages/*.ppm
RUN rm -rf seed-corpora

COPY build.sh $SRC/
