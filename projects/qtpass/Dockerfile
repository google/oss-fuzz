# Copyright 2026 Google LLC
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

# QtPass's floor is Qt 6.8+ (see CLAUDE.md); pin the same patch version the
# project's own CI builds against, via aqtinstall rather than distro
# packages, so the fuzz build tracks a known-good Qt instead of whatever
# the base image's Ubuntu release happens to carry.
RUN apt-get update && apt-get install -y python3-pip libglib2.0-0 libgl-dev
RUN pip3 install aqtinstall
RUN aqt install-qt linux desktop 6.8.3 linux_gcc_64 --outputdir /opt/qt
ENV QMAKE=/opt/qt/6.8.3/gcc_64/bin/qmake
ENV LD_LIBRARY_PATH=/opt/qt/6.8.3/gcc_64/lib:$LD_LIBRARY_PATH

RUN git clone --depth 1 https://github.com/IJHack/QtPass.git

WORKDIR QtPass
COPY build.sh $SRC/
