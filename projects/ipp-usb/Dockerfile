# Copyright 2025 Google LLC
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

FROM gcr.io/oss-fuzz-base/base-builder-go
RUN apt-get update && apt-get install -y \
    make \
    pkg-config \
    libusb-1.0-0-dev \
    libudev-dev \
    libudev1 \
    libavahi-client-dev \
    libavahi-common-dev \
    libavahi-client3 \
    libavahi-core7 \
    libavahi-common3 \
    linux-tools-generic \
    kmod \
 && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/OpenPrinting/ipp-usb $SRC/ipp-usb
RUN git clone --depth 1 https://github.com/OpenPrinting/go-mfp $SRC/go-mfp
RUN git clone --depth 1 https://github.com/OpenPrinting/fuzzing $SRC/fuzzing

WORKDIR $SRC/fuzzing
COPY build.sh $SRC/