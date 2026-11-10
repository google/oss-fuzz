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
# Install Git and base dependences.
RUN apt-get update && apt-get install -y devscripts equivs \
	build-essential git-core cmake ninja-build pkg-config ccache

RUN git clone --depth 1 https://github.com/FreeRDP/FreeRDP.git

WORKDIR FreeRDP

# Install all dependencies required by the nightly package.
# NOTE (local-only workaround): libpipewire-0.3-dev / libspa-0.2-dev have no
# candidate in the base-builder (focal) apt sources, which poisons the whole
# build-deps metapackage. They are audio-routing deps unused by the fuzz
# targets, so strip them locally to unblock the image build.
RUN sed -i '/libpipewire-0.3-dev/d;/libspa-0.2-dev/d' packaging/deb/freerdp-nightly/control
RUN mk-build-deps --install --tool 'apt-get --yes --no-install-recommends' packaging/deb/freerdp-nightly/control

COPY run_tests.sh build.sh generate_seeds.py $SRC/
