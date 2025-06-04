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

FROM gcr.io/oss-fuzz-base/base-builder-jvm

RUN curl -L https://archive.apache.org/dist/maven/maven-3/3.9.9/binaries/apache-maven-3.9.9-bin.zip -o maven.zip && \
    unzip maven.zip -d $SRC/maven && \
    rm -rf maven.zip
ENV MVN $SRC/maven/apache-maven-3.9.9/bin/mvn

RUN git clone --depth 1 https://github.com/powsybl/powsybl-core 
RUN git clone --depth 1 https://github.com/powsybl/powsybl-diagram
RUN git clone --depth 1 https://github.com/powsybl/powsybl-metrix
RUN git clone --depth 1 https://github.com/powsybl/powsybl-open-rao
RUN git clone --depth 1 https://github.com/powsybl/powsybl-dynawo
RUN git clone --depth 1 https://github.com/powsybl/powsybl-entsoe
RUN git clone --depth 1 https://github.com/powsybl/powsybl-open-loadflow

# For corpus
RUN git clone --depth 1 https://github.com/arthurscchan/powsybl-seed-corpus

COPY build.sh $SRC/
COPY *Fuzzer.java $SRC/
WORKDIR $SRC/
