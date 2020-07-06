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

FROM gcr.io/oss-fuzz-base/base-builder

RUN go get -u -d github.com/google/syzkaller/prog

# Dependency for one of the fuzz targets.
# Note: this should not be necessary because this package is in syzkaller/vendor.
RUN go get github.com/ianlancetaylor/demangle

WORKDIR /root/go/src/github.com/google/syzkaller
COPY build.sh $SRC/
