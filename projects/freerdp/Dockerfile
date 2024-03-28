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
	build-essential \
	ccache \
	cmake \
	docbook-xsl \
	git-core \
	krb5-multidev \
	libasound2-dev \
	libavcodec-dev \
	libavutil-dev \
	libcairo2-dev \
	libcjson-dev \
	libcups2-dev \
	libdbus-glib-1-dev \
	libfaac-dev \
	libfaad-dev \
	libfuse3-dev \
	libfuse-dev \
	libgsm1-dev \
	libicu-dev \
	libjpeg-dev \
	libkrb5-dev \
	libopus-dev \
	libpam0g-dev \
	libpcsclite-dev \
	libpkcs11-helper1 \
	libpkcs11-helper1-dev \
	libpng-dev \
	libpulse-dev \
	libsdl2-2.0-0 \
	libsdl2-dev \
	libsdl2-image-dev \
	libsdl2-ttf-dev \
	libsoxr-dev \
	libssl-dev \
	libswresample-dev \
	libswscale-dev \
	libsystemd-dev \
	libudev-dev \
	liburiparser-dev \
	libusb-1.0-0-dev \
	libwayland-dev \
	libwebkit2gtk-4.0-dev \
	libwebp-dev \
	libx11-dev \
	libxcb-damage0-dev \
	libxcursor-dev \
	libxdamage-  dev \
	libxdamage-dev \
	libxext-dev \
	libxfixes-dev \
	libxi-dev \
	libxinerama-dev \
	libxkbcommon-dev \
	libxkbfile-dev \
	libxml2-dev \
	libxrandr-dev \
	libxrender-dev \
	libxtst-dev \
	libxv-dev \
	ninja-build \
	ocl-icd-opencl-dev \
	opencl-c-headers \
	opencl-headers \
	opensc-pkcs11 \
	pkg-config \
	uuid-dev \
	xsltproc \
	xsltproc libsdl2-dev \
	zlib1g-dev

RUN git clone --depth 1 https://github.com/FreeRDP/FreeRDP.git

WORKDIR FreeRDP
COPY build.sh $SRC/
