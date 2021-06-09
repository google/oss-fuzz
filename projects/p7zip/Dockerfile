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

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y make autoconf automake libtool wget
#RUN git clone --depth 1 https://github.com/jinfeihan57/p7zip p7zip     # or use other version control
RUN wget https://sourceforge.net/projects/p7zip/files/p7zip/16.02/p7zip_16.02_src_all.tar.bz2 && \
    tar -xf p7zip_16.02_src_all.tar.bz2 && \
    mv p7zip_16.02 p7zip
WORKDIR p7zip
COPY build.sh $SRC/


RUN mkdir CPP/7zip/CMAKE/fuzzer
COPY fuzz-CMakeLists.txt $SRC/p7zip/CPP/7zip/CMAKE/fuzzer/CMakeLists.txt
COPY fuzz_*.cpp $SRC/p7zip/CPP/7zip/CMAKE/ 
COPY tmp_CMakeLists.txt $SRC/p7zip/CPP/7zip/CMAKE/CMakeLists.txt
#COPY fuzz-CMakeLists.txt $SRC/fuzz-CMakeLists.txt
