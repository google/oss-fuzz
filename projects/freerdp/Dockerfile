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

# See https://github.com/FreeRDP/FreeRDP/wiki/Compilation
RUN apt-get update && apt-get install -y \
	build-essential git-core cmake ninja-build pkg-config zlib1g-dev ccache \
	libx11-dev libxext-dev libxinerama-dev libxcursor-dev libxkbfile-dev \
	libxv-dev libxi-dev libxdamage-dev libxrender-dev libxrandr-dev \
	libssl-dev libasound2-dev libcups2-dev libpulse-dev libcairo2-dev \
	libavutil-dev libavcodec-dev libusb-1.0-0-dev libicu-dev \
	libpkcs11-helper1-dev libpkcs11-helper1 libsdl2-ttf-dev \
	libwayland-dev libpam0g-dev libxcb-damage0-dev ccache libxtst-dev \
	libfuse-dev libsystemd-dev libsoxr-dev libsdl2-dev docbook-xsl \
	libkrb5-dev krb5-multidev libcjson-dev libswscale-dev libswresample-dev \
	libpcsclite-dev xsltproc libsdl2-dev

RUN git clone --depth 1 https://github.com/FreeRDP/FreeRDP.git

WORKDIR FreeRDP
COPY build.sh $SRC/
