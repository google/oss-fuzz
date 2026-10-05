# Copyright 2026 Google LLC
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
RUN apt-get update && apt-get install -y autoconf automake libtool
RUN git clone --depth 1 --branch 0.2.5 https://github.com/yaml/libyaml
RUN git clone https://github.com/unjs/md4x

# Dictionaries:
RUN git clone --depth 1 https://github.com/google/fuzzing && \
    mv fuzzing/dictionaries/markdown.dict $SRC/fuzz-mdhtml.dict && \
    cp $SRC/fuzz-mdhtml.dict $SRC/fuzz-mdast.dict && \
    cp $SRC/fuzz-mdhtml.dict $SRC/fuzz-mdansi.dict && \
    cp $SRC/fuzz-mdhtml.dict $SRC/fuzz-mdtext.dict && \
    cp $SRC/fuzz-mdhtml.dict $SRC/fuzz-mdmeta.dict && \
    cp $SRC/fuzz-mdhtml.dict $SRC/fuzz-mdheal.dict && \
    rm -rf fuzzing

# Seed corpus (shared across all fuzzers):
RUN zip -j $SRC/seed_corpus.zip $SRC/md4x/test/fuzzers/seed-corpus/*.md

WORKDIR $SRC/md4x
COPY build.sh $SRC/
