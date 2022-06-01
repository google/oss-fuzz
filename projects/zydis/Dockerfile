# Copyright 2021 Google Inc.
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

ADD https://zydis.re/fuzzing-corpora/ZydisFuzzDecoder_seed_corpus.zip \
    $SRC/ZydisFuzzDecoder_seed_corpus.zip
ADD https://zydis.re/fuzzing-corpora/ZydisFuzzEncoder_seed_corpus.zip \
    $SRC/ZydisFuzzEncoder_seed_corpus.zip
ADD https://zydis.re/fuzzing-corpora/ZydisFuzzReEncoding_seed_corpus.zip \
    $SRC/ZydisFuzzReEncoding_seed_corpus.zip

COPY build.sh $SRC/

RUN git clone --recursive https://github.com/zyantific/zydis.git
WORKDIR zydis
