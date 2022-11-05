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

RUN curl -L https://downloads.apache.org/maven/maven-3/3.6.3/binaries/apache-maven-3.6.3-bin.zip -o maven.zip && \
    unzip maven.zip -d $SRC/maven && \
    rm -rf maven.zip

ENV MVN $SRC/maven/apache-maven-3.6.3/bin/mvn

# Compress
RUN git clone --depth 1 https://github.com/apache/commons-compress.git

# Imaging
RUN git clone --depth 1 https://github.com/apache/commons-imaging.git

# Geometry
RUN git clone --depth 1 https://github.com/apache/commons-geometry.git

# Math
RUN git clone --depth 1 https://github.com/apache/commons-math.git

# Bcel
RUN git clone --depth 1 https://github.com/apache/commons-bcel.git

# Beanutils
RUN git clone --depth 1 https://github.com/apache/commons-beanutils.git

# Cli
RUN git clone --depth 1 https://github.com/apache/commons-cli.git

# Codec
RUN git clone --depth 1 https://github.com/apache/commons-codec.git

# Collections
RUN git clone --depth 1 https://github.com/apache/commons-collections.git

# Configuration
RUN git clone --depth=1 https://github.com/apache/commons-configuration.git

# IO
RUN git clone --depth 1 https://github.com/apache/commons-io.git

# JXPath
RUN git clone --depth 1 https://github.com/apache/commons-jxpath.git

# Lang
RUN git clone --depth 1 https://github.com/apache/commons-lang

# Logging
RUN git clone --depth 1 https://github.com/apache/commons-logging

# Dictionaries
RUN git clone --depth 1 https://github.com/google/fuzzing && \
    cp fuzzing/dictionaries/zip.dict $SRC/CompressZipFuzzer.dict && \
    cp fuzzing/dictionaries/gif.dict $SRC/ImagingGifFuzzer.dict && \
    cp fuzzing/dictionaries/jpeg.dict $SRC/ImagingJpegFuzzer.dict && \
    cp fuzzing/dictionaries/png.dict $SRC/ImagingPngFuzzer.dict && \
    cp fuzzing/dictionaries/tiff.dict $SRC/ImagingTiffFuzzer.dict && \
    cp fuzzing/dictionaries/xml.dict $SRC/XMLConfigurationLoadFuzzer.dict && \
    cp fuzzing/dictionaries/yaml.dict $SRC/YAMLConfigurationReadFuzzer.dict && \
    cp fuzzing/dictionaries/yaml.dict $SRC/YAMLConfigurationWriteFuzzer.dict && \
    cp fuzzing/dictionaries/json.dict $SRC/JSONConfigurationReadFuzzer.dict && \
    cp fuzzing/dictionaries/json.dict $SRC/JSONConfigurationWriteFuzzer.dict && \
    cp fuzzing/dictionaries/xml.dict $SRC/XmlFuzzer.dict && \
    cp fuzzing/dictionaries/xml.dict $SRC/JXPathFuzzer.dict && \
    cp fuzzing/dictionaries/html.dict $SRC/EscapeHtmlFuzzer.dict && \
    cat fuzzing/dictionaries/json.dict fuzzing/dictionaries/xml.dict > $SRC/StringEscapeUtilsFuzzer.dict && \
    rm -rf fuzzing

# Seed corpus (go-fuzz-corpus) 
RUN git clone --depth 1 https://github.com/dvyukov/go-fuzz-corpus && \
    zip -j $SRC/CompressTarFuzzer_seed_corpus.zip go-fuzz-corpus/tar/corpus/* && \
    zip -j $SRC/CompressZipFuzzer_seed_corpus.zip go-fuzz-corpus/zip/corpus/* && \
    zip -j $SRC/ImagingBmpFuzzer_seed_corpus.zip go-fuzz-corpus/bmp/corpus/* && \
    zip -j $SRC/ImagingGifFuzzer_seed_corpus.zip go-fuzz-corpus/gif/corpus/* && \
    zip -j $SRC/ImagingJpegFuzzer_seed_corpus.zip go-fuzz-corpus/jpeg/corpus/* && \
    zip -j $SRC/ImagingPngFuzzer_seed_corpus.zip go-fuzz-corpus/png/corpus/* && \
    zip -j $SRC/ImagingTiffFuzzer_seed_corpus.zip go-fuzz-corpus/tiff/corpus/* && \
    zip -j $SRC/ImagingTiffFuzzer_seed_corpus.zip go-fuzz-corpus/tiff/corpus/* && \
    zip -q $SRC/XMLConfigurationLoadFuzzer_seed_corpus.zip go-fuzz-corpus/xml/corpus/* && \
    zip -q $SRC/JSONConfigurationReadFuzzer_seed_corpus.zip go-fuzz-corpus/json/corpus/* && \
    zip -q $SRC/JSONConfigurationWriteFuzzer_seed_corpus.zip go-fuzz-corpus/json/corpus/* && \
    zip -j $SRC/XmlFuzzer_seed_corpus.zip go-fuzz-corpus/xml/corpus/* && \
    zip -j $SRC/JXPathFuzzer_seed_corpus.zip go-fuzz-corpus/xml/corpus/* && \
    zip -q $SRC/EscapeHtmlFuzzer_seed_corpus.zip go-fuzz-corpus/htmltemplate/corpus/* && \
    zip -q $SRC/StringEscapeUtilsFuzzer_seed_corpus.zip go-fuzz-corpus/json/corpus/* go-fuzz-corpus/csv/corpus/* && \
    rm -rf go-fuzz-corpus

RUN zip -uj $SRC/CompressTarFuzzer_seed_corpus.zip commons-compress/src/test/resources/*.tar && \
    zip -uj $SRC/CompressZipFuzzer_seed_corpus.zip commons-compress/src/test/resources/*.zip && \
    zip -j $SRC/CompressSevenZFuzzer_seed_corpus.zip commons-compress/src/test/resources/bla.7z

# Copy build script and all fuzzers
COPY . $SRC/
WORKDIR $SRC/
