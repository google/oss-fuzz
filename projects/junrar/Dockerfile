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

RUN curl -L https://services.gradle.org/distributions/gradle-7.4.2-bin.zip -o gradle.zip && \
    unzip gradle.zip -d $SRC/gradle && \
    rm -rf gradle.zip

ENV GRADLE_HOME $SRC/gradle/gradle-7.4.2
ENV PATH $GRADLE_HOME/bin:$PATH

# Dict
# no existing rar.dict found on web, build rar dict manually later

# Seeds
RUN git clone --depth 1 https://github.com/strongcourage/fuzzing-corpus.git && \
    zip -j $SRC/JunrarFuzzer_seed_corpus.zip fuzzing-corpus/rar/* && \
    rm -rf fuzzing-corpus

RUN git clone --depth 1 https://github.com/junrar/junrar.git junrar

COPY build.sh $SRC/
COPY JunrarFuzzer.java $SRC/
WORKDIR $SRC/junrar
