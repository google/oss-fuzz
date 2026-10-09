# Copyright 2025 Google LLC
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

#We need a modern version of mupdf-tools.
#In the version of mutools that is brought in with oss-fuzz base as of 28 Aug 2025,
#only some font types have "font-" prepended as their name. This breaks
#globbing, and, separately, we don't want to use such an old version.

#So, we can either build it or simply use an OS that comes with a more recent version
#I'm choosing the latter.
FROM ubuntu:questing-20250806 AS base

RUN set -eux \
    && apt-get update \
    && apt-get install --yes --no-install-recommends \
    mupdf-tools curl ca-certificates unzip zip && \
    apt-get clean

#pull an arbitrary zip of 1k pdfs
RUN mkdir /work && \
     curl -L https://digitalcorpora.s3.amazonaws.com/corpora/files/CC-MAIN-2021-31-PDF-UNTRUNCATED/zipfiles/5000-5999/5136.zip \
    --output /work/PDFExtractTextFuzzer_seed_corpus.zip
COPY extract-fonts.sh /work/extract-fonts.sh
RUN cd /work && /bin/bash extract-fonts.sh && rm extract-fonts.sh


FROM gcr.io/oss-fuzz-base/base-builder-jvm

COPY --from=base /work/*_seed_corpus.zip $SRC

RUN git clone --depth 1 https://github.com/google/fuzzing && \
    cp fuzzing/dictionaries/pdf.dict $SRC/PDFStreamParserFuzzer.dict && \
    cp fuzzing/dictionaries/pdf.dict $SRC/PDFWriteReadFuzzer.dict && \
    rm -rf fuzzing

RUN curl -L https://archive.apache.org/dist/maven/maven-3/3.9.11/binaries/apache-maven-3.9.11-bin.zip -o maven.zip && \
    unzip maven.zip -d $SRC/maven && \
    rm -rf maven.zip

# if not set python infra helper cannot be used for local testing
ENV MVN=$SRC/maven/apache-maven-3.9.11/bin/mvn

COPY project-parent $SRC/project-parent/
RUN rm -rf $SRC/project-parent/pdfbox
RUN git clone --depth 1 https://github.com/apache/pdfbox/ $SRC/project-parent/pdfbox

COPY build.sh $SRC/
WORKDIR $SRC/project-parent/pdfbox