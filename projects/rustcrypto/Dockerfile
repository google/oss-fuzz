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

# Held back because of github.com/google/oss-fuzz/pull/8313
# Please fix failure and upgrade.
FROM gcr.io/oss-fuzz-base/base-builder@sha256:111d6b9d3a52bd3392602c71dc8936c628607a7a9bc86d381db7586f9b1e840f
RUN apt-get update && apt-get install -y make autoconf automake libtool wget python
RUN git clone --depth 1 https://github.com/guidovranken/cryptofuzz
RUN git clone --depth 1 https://github.com/randombit/botan.git
RUN wget https://boostorg.jfrog.io/artifactory/main/release/1.74.0/source/boost_1_74_0.tar.bz2
RUN wget https://storage.googleapis.com/pub/gsutil.tar.gz -O $SRC/gsutil.tar.gz
RUN tar zxf $SRC/gsutil.tar.gz
ENV PATH="${PATH}:$SRC/gsutil"
# Retrieve corpus from the OSS-Fuzz 'cryptofuzz' project
RUN gsutil cp gs://cryptofuzz-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/cryptofuzz_cryptofuzz-openssl/public.zip $SRC/corpus_cryptofuzz.zip
COPY build.sh $SRC/
