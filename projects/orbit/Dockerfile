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
RUN apt-get update && apt-get install -y m4 libglu1-mesa-dev mesa-common-dev \
  libxmu-dev libxi-dev pkg-config libxxf86vm-dev patchelf

ADD https://github.com/google/orbit/archive/main.tar.gz $SRC/
RUN mkdir -p $SRC/orbit && tar -xzf $SRC/main.tar.gz \
  -C $SRC/orbit/ --strip-components 1; rm -f $SRC/main.tar.gz
WORKDIR $SRC/orbit
COPY build.sh $SRC/
COPY default.options $SRC/

# That's a hack. The service needs to have a more recent kernel than what the
# container provides. But this code is not going to be called from the fuzz-
# tests, so we should be fine here.
ADD https://raw.githubusercontent.com/torvalds/linux/v5.7/include/uapi/linux/perf_event.h /usr/include/linux/perf_event.h
