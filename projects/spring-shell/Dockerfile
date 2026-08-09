# Copyright 2022 Google LLC
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

FROM gcr.io/oss-fuzz-base/base-builder-jvm

RUN apt update && apt install -y openjdk-17-jdk

RUN git clone --depth 1 https://github.com/spring-projects/spring-shell.git spring-shell     # or use other version control
COPY add-shadow-*.patch $SRC/
RUN  cd spring-shell && (for i in ${SRC}/add-shadow-*.patch; do tr -d '\015' < $i | git apply; done )

COPY build.sh $SRC/
COPY core $SRC/core/
COPY standard $SRC/standard/
COPY table $SRC/table/

WORKDIR spring-shell