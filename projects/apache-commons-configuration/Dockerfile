# Copyright 2022 Google LLC
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

# Install a working version of Maven
RUN curl -L https://archive.apache.org/dist/maven/maven-3/3.6.3/binaries/apache-maven-3.6.3-bin.zip -o maven.zip && \
    unzip maven.zip -d $SRC/maven && \
    rm -f maven.zip

ENV MVN $SRC/maven/apache-maven-3.6.3/bin/mvn

# Clone the commons-configuration library source code
RUN git clone --depth=1 "https://gitbox.apache.org/repos/asf/commons-configuration.git" commons-configuration

# Get the dictionaries
RUN git clone --depth=1 "https://github.com/google/fuzzing" fuzzing
RUN cp fuzzing/dictionaries/xml.dict $SRC/XMLConfigurationLoadFuzzer.dict

RUN cp fuzzing/dictionaries/yaml.dict $SRC/YAMLConfigurationReadFuzzer.dict
RUN cp $SRC/YAMLConfigurationReadFuzzer.dict $SRC/YAMLConfigurationWriteFuzzer.dict

RUN cp fuzzing/dictionaries/json.dict $SRC/JSONConfigurationReadFuzzer.dict
RUN cp $SRC/JSONConfigurationReadFuzzer.dict $SRC/JSONConfigurationWriteFuzzer.dict

COPY ini.dict $SRC/INIConfigurationReadFuzzer.dict
RUN cp $SRC/INIConfigurationReadFuzzer.dict $SRC/INIConfigurationWriteFuzzer.dict

# Get the corpora
RUN git clone --depth=1 "https://github.com/dvyukov/go-fuzz-corpus" corpora
RUN zip -q $SRC/XMLConfigurationLoadFuzzer_seed_corpus.zip corpora/xml/corpus/*

RUN zip -q $SRC/JSONConfigurationReadFuzzer_seed_corpus.zip corpora/json/corpus/*
RUN cp $SRC/JSONConfigurationReadFuzzer_seed_corpus.zip $SRC/JSONConfigurationWriteFuzzer_seed_corpus.zip

# Copy the build script and all the fuzztargets
COPY build.sh $SRC/
COPY *Fuzzer.java $SRC/
WORKDIR $SRC/commons-configuration
