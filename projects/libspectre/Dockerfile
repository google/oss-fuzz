# Copyright 2020 Google Inc.
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


RUN apt-get update && \
    apt-get install -y pkg-config make automake libtool wget

RUN git clone --depth 1 https://gitlab.freedesktop.org/libspectre/libspectre.git

RUN wget -O $SRC/libspectre/ghostscript-9.53.3.tar.gz https://github.com/ArtifexSoftware/ghostpdl-downloads/releases/download/gs9533/ghostscript-9.53.3.tar.gz
RUN tar xvzf $SRC/libspectre/ghostscript-9.53.3.tar.gz --directory $SRC/libspectre/
RUN mv $SRC/libspectre/ghostscript-9.53.3 $SRC/libspectre/ghostscript

WORKDIR $SRC/libspectre/
COPY build.sh $SRC/
# This is to fix Fuzz Introspector build by using LLVM old pass manager
# re https://github.com/ossf/fuzz-introspector/issues/305
ENV OLD_LLVMPASS 1
