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
    apt-get install -y wget tar


RUN git clone --depth 1 https://github.com/nothings/stb.git

RUN mkdir $SRC/stbi # CIFuzz workaround

RUN wget -O $SRC/stbi/gif.tar.gz https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/imagetestsuite/imagetestsuite-gif-1.00.tar.gz
RUN wget -O $SRC/stbi/jpg.tar.gz https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/imagetestsuite/imagetestsuite-jpg-1.00.tar.gz
RUN wget -O $SRC/stbi/bmp.zip http://entropymine.com/jason/bmpsuite/releases/bmpsuite-2.6.zip
RUN wget -O $SRC/stbi/tga.zip https://github.com/richgel999/tga_test_files/archive/master.zip

RUN wget -O $SRC/stbi/gif.dict https://raw.githubusercontent.com/mirrorer/afl/master/dictionaries/gif.dict

# Maintain compatibility with master branch until a new release
RUN cp $SRC/stbi/gif.tar.gz $SRC/stbi/jpg.tar.gz $SRC/stbi/bmp.zip $SRC/stbi/gif.dict $SRC/stb

WORKDIR stb
COPY build.sh $SRC/
