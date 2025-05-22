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

# checkout all sources needed to build your project
RUN git clone --depth 1 https://skia.googlesource.com/skcms.git

RUN wget -O $SRC/skcms/iccprofile_seed_corpus.zip https://storage.googleapis.com/skia-fuzzer/oss-fuzz/iccprofile_seed_corpus.zip

# current directory for build script
WORKDIR skcms

RUN apt-get update && \
    apt-get install -y systemd && \
    wget https://download.docker.com/linux/ubuntu/dists/focal/pool/stable/amd64/docker-ce-cli_20.10.8~3-0~ubuntu-focal_amd64.deb -O /tmp/docker-ce.deb && \
    dpkg -i /tmp/docker-ce.deb && \
    rm /tmp/docker-ce.deb

COPY build.sh $SRC/

COPY iccprofile.options iccprofile.dict $SRC/skcms/