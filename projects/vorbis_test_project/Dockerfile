# Copyright 2018 Google Inc.
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
RUN apt-get update && apt-get install -y make autoconf automake ffmpeg libtool pkg-config python3 wget
RUN python3 -m pip install --upgrade pip && python3 -m pip install corpus-replicator
RUN git clone --depth 1 https://gitlab.xiph.org/xiph/ogg.git
RUN git clone --depth 1 https://gitlab.xiph.org/xiph/vorbis.git
RUN corpus-replicator -o decode_corpus audio_vorbis_ogg_libvorbis.yml audio
# TODO: remove `people.xiph.org` lines once upstream build script is updated
RUN mkdir people.xiph.org/
RUN touch people.xiph.org/dummy.ogg
WORKDIR vorbis
COPY build.sh $SRC/
