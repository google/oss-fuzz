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
RUN go get 	github.com/vitessio/vitess \
		vitess.io/vitess/go/bytes2 \
		vitess.io/vitess/go/sqltypes \
		vitess.io/vitess/go/vt/log \
		vitess.io/vitess/go/vt/proto/query \
		vitess.io/vitess/go/vt/proto/vtrpc \
		vitess.io/vitess/go/vt/vterrors \
		vitess.io/vitess/go/vt/vtgate/evalengine
COPY build.sh $SRC/
WORKDIR $SRC/
