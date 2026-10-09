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
RUN apt-get update && apt-get install -y wget cmake libjpeg-turbo8-dev zlib1g-dev libxmp-dev
RUN git clone https://android.googlesource.com/platform/external/dng_sdk/

# For seed corpus
RUN git clone --depth=1 https://github.com/ianare/exif-samples exif-samples
RUN git clone --depth=1 https://github.com/image-rs/image-tiff image-tiff
RUN git clone --depth=1 https://github.com/yigolden/TiffLibrary TiffLibrary

COPY build.sh $SRC/
COPY *_fuzzer.cpp $SRC/
WORKDIR dng_sdk
