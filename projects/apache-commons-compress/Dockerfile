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

RUN curl -L https://archive.apache.org/dist/maven/maven-3/3.9.5/binaries/apache-maven-3.9.5-bin.zip -o maven.zip && \
    unzip maven.zip -d $SRC/maven && \
    rm -rf maven.zip

ENV MVN $SRC/maven/apache-maven-3.9.5/bin/mvn

# Dictionaries
RUN git clone --depth 1 https://github.com/google/fuzzing && \
    mv fuzzing/dictionaries/zip.dict $SRC/CompressZipFuzzer.dict && \
    mv fuzzing/dictionaries/bz2.dict $SRC/CompressorBZip2Fuzzer.dict && \
    rm -rf fuzzing

# Seed corpus (go-fuzz-corpus)
RUN git clone --depth 1 https://github.com/dvyukov/go-fuzz-corpus && \
    zip -j0 $SRC/CompressTarFuzzer_seed_corpus.zip go-fuzz-corpus/tar/corpus/* && \
    zip -j0 $SRC/CompressZipFuzzer_seed_corpus.zip go-fuzz-corpus/zip/corpus/* && \
    zip -j0 $SRC/CompressorBZip2Fuzzer_seed_corpus.zip go-fuzz-corpus/bzip2/corpus/* && \
    zip -j0 $SRC/CompressorGzipFuzzer_seed_corpus.zip go-fuzz-corpus/gzip/corpus/* && \
    zip -j0 $SRC/CompressorSnappyFuzzer_seed_corpus.zip go-fuzz-corpus/snappy/corpus/* && \
    rm -rf go-fuzz-corpus

# Checkout out Compress source code
RUN git clone --depth 1 https://gitbox.apache.org/repos/asf/commons-compress.git

# Seed corpus (Compress source code)
RUN \
    zip -j0  $SRC/ArchiverArFuzzer_seed_corpus.zip commons-compress/src/test/resources/*.ar && \
    zip -uj0 $SRC/ArchiverArFuzzer_seed_corpus.zip commons-compress/src/test/resources/archives/*.ar && \
    zip -j0  $SRC/ArchiverArjFuzzer_seed_corpus.zip commons-compress/src/test/resources/*.arj && \
    zip -j0  $SRC/ArchiverCpioFuzzer_seed_corpus.zip commons-compress/src/test/resources/*.cpio && \
    zip -uj0 $SRC/ArchiverCpioFuzzer_seed_corpus.zip commons-compress/src/test/resources/archives/*.cpio && \
    zip -j0  $SRC/ArchiverDumpFuzzer_seed_corpus.zip commons-compress/src/test/resources/*.dump && \
    zip -uj0 $SRC/ArchiverDumpFuzzer_seed_corpus.zip commons-compress/src/test/resources/org/apache/commons/compress/dump/*.dump && \
    zip -j0  $SRC/CompressSevenZFuzzer_seed_corpus.zip commons-compress/src/test/resources/*.7z && \
    zip -uj0 $SRC/CompressTarFuzzer_seed_corpus.zip commons-compress/src/test/resources/*.tar && \
    zip -uj0 $SRC/CompressTarFuzzer_seed_corpus.zip commons-compress/src/test/resources/archives/*.tar && \
    zip -uj0 $SRC/CompressTarFuzzer_seed_corpus.zip commons-compress/src/test/resources/longpath/*.tar && \
    zip -uj0 $SRC/CompressTarFuzzer_seed_corpus.zip commons-compress/src/test/resources/longsymlink/*.tar && \
    zip -uj0 $SRC/CompressZipFuzzer_seed_corpus.zip commons-compress/src/test/resources/*.zip

RUN \
    zip -uj0 $SRC/CompressorBZip2Fuzzer_seed_corpus.zip commons-compress/src/test/resources/*.bz2 && \
    zip -j0  $SRC/CompressorDeflate64Fuzzer_seed_corpus.zip commons-compress/src/test/resources/*.deflate && \
    zip -uj0 $SRC/CompressorGzipFuzzer_seed_corpus.zip commons-compress/src/test/resources/*.gz && \
    zip -j0  $SRC/CompressorLZ4Fuzzer_seed_corpus.zip commons-compress/src/test/resources/*lz4 && \
    zip -j0  $SRC/CompressorPack200Fuzzer_seed_corpus.zip commons-compress/src/test/resources/*.pack && \
    zip -uj0 $SRC/CompressorPack200Fuzzer_seed_corpus.zip commons-compress/src/test/resources/pack200/*.pack && \
    zip -uj0 $SRC/CompressorSnappyFuzzer_seed_corpus.zip commons-compress/src/test/resources/*.sz && \
    zip -j0  $SRC/CompressorZFuzzer_seed_corpus.zip commons-compress/src/test/resources/*.Z

# Copy some corpuses and dictionaries
RUN \
    cp $SRC/CompressTarFuzzer_seed_corpus.zip $SRC/ArchiverTarStreamFuzzer_seed_corpus.zip && \
    cp $SRC/CompressZipFuzzer.dict $SRC/ArchiverZipStreamFuzzer.dict && \
    cp $SRC/CompressZipFuzzer_seed_corpus.zip $SRC/ArchiverZipStreamFuzzer_seed_corpus.zip

# Copy build script, all fuzzers and supporting files
COPY build.sh $SRC/
COPY *.java $SRC/
WORKDIR $SRC/
