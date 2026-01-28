# Copyright 2023 Google LLC
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

# Main repo
RUN git clone --depth 1 -b develop https://github.com/eclipse-mosquitto/mosquitto ${SRC}/mosquitto

# Build LPM separately to other deps to allow better caching
RUN apt-get update && apt-get install -y \
	autoconf \
	binutils \
	cmake \
	liblzma-dev \
	libtool \
	libz-dev \
	make  \
	ninja-build \
	pkg-config
RUN git clone --depth 1 https://github.com/google/libprotobuf-mutator.git
RUN (mkdir LPM && cd LPM && cmake ../libprotobuf-mutator -GNinja -DLIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF=ON \
    -DLIB_PROTO_MUTATOR_TESTING=OFF -DCMAKE_BUILD_TYPE=Release && ninja)

# Get dependencies
RUN $SRC/mosquitto/fuzzing/scripts/oss-fuzz-dependencies.sh

WORKDIR $SRC/mosquitto
COPY build.sh $SRC/
