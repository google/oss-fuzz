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

FROM gcr.io/oss-fuzz-base/base-builder-jvm:ubuntu-24-04

RUN wget https://services.gradle.org/distributions/gradle-8.10-bin.zip -O gradle.zip && \
    unzip gradle.zip -d $SRC/gradle && \
    rm -rf gradle.zip

ENV GRADLE=$SRC/gradle/gradle-8.10/bin/gradle

RUN apt-get update && apt-get install -y zip

RUN git clone --depth 1 https://github.com/bcgit/bc-java.git bc-java

# seed material for the CMS, ASN.1, OpenPGP, PKCS#12, TSP and CMP fuzzers: a few small directories of the test data
# repository rather than all of it
RUN git clone --depth 1 --filter=blob:none --sparse https://github.com/bcgit/bc-test-data.git bc-test-data && \
    git -C bc-test-data sparse-checkout set asn1 rfc4134 pkix/cms pkix/pkcs12 pgpdata openpgp/openpgp-pqc tsp cmp

COPY build.sh $SRC/
COPY *Fuzzer.java *SeedGenerator.java *.dict $SRC/
WORKDIR $SRC/bc-java
