# Copyright 2019 Google Inc.
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

FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04

RUN git clone https://gitlab.com/samba-team/samba samba

# Upstream samba dropped ubuntu2004 in commit 313a630 (2026-04-08) and
# build_image.sh still has DIST=ubuntu2004 hard-coded. The OSS-Fuzz base-builder
# for this project is Ubuntu 24.04 (see base_os_version in project.yaml), so
# point build_image.sh at the matching ubuntu2404 generated-dist before running.
RUN sed -i 's/^DIST=ubuntu2004/DIST=ubuntu2404/' \
        samba/lib/fuzzing/oss-fuzz/build_image.sh

RUN samba/lib/fuzzing/oss-fuzz/build_image.sh

WORKDIR samba
COPY build.sh $SRC/
