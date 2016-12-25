# Copyright 2016 Google Inc.
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

FROM ossfuzz/base-libfuzzer
MAINTAINER mike.aizatsky@gmail.com
RUN apt-get install -y make autoconf libtool libarchive-dev

RUN git clone --depth 1 git://git.sv.nongnu.org/freetype/freetype2.git
WORKDIR freetype2
COPY build.sh $SRC/

# Get some files for the seed corpus
RUN wget https://github.com/adobe-fonts/adobe-variable-font-prototype/releases/download/1.001/AdobeVFPrototype.otf


# Put all seed files into $OUT/ftfuzzer_seed_corpus.zip
RUN zip -j $OUT/ftfuzzer_seed_corpus.zip $(find . -name '*.otf')
