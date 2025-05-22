# Copyright 2021 Google LLC
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

FROM gcr.io/oss-fuzz-base/base-builder-jvm

RUN curl -L https://archive.apache.org/dist/maven/maven-3/3.6.3/binaries/apache-maven-3.6.3-bin.zip -o maven.zip && \
    unzip maven.zip -d $SRC/maven && \
    rm -rf maven.zip

ENV MVN $SRC/maven/apache-maven-3.6.3/bin/mvn

# Dictionaries
RUN git clone --depth 1 https://github.com/google/fuzzing && \
    mv fuzzing/dictionaries/gif.dict $SRC/ImagingGifFuzzer.dict && \
    mv fuzzing/dictionaries/jpeg.dict $SRC/ImagingJpegFuzzer.dict && \
    mv fuzzing/dictionaries/png.dict $SRC/ImagingPngFuzzer.dict && \
    mv fuzzing/dictionaries/tiff.dict $SRC/ImagingTiffFuzzer.dict && \
    rm -rf fuzzing

# Seed corpus (go-fuzz-corpus)
RUN git clone --depth 1 https://github.com/dvyukov/go-fuzz-corpus && \
    zip -j $SRC/ImagingBmpFuzzer_seed_corpus.zip go-fuzz-corpus/bmp/corpus/* && \
    zip -j $SRC/ImagingGifFuzzer_seed_corpus.zip go-fuzz-corpus/gif/corpus/* && \
    zip -j $SRC/ImagingJpegFuzzer_seed_corpus.zip go-fuzz-corpus/jpeg/corpus/* && \
    zip -j $SRC/ImagingPngFuzzer_seed_corpus.zip go-fuzz-corpus/png/corpus/* && \
    zip -j $SRC/ImagingTiffFuzzer_seed_corpus.zip go-fuzz-corpus/tiff/corpus/* && \
    rm -rf go-fuzz-corpus

# Imaging
RUN git clone --depth 1 https://gitbox.apache.org/repos/asf/commons-imaging.git

# Copy build script and all fuzzers
COPY build.sh $SRC/
COPY *Fuzzer.java $SRC/
WORKDIR $SRC/
