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

WORKDIR ${SRC}
#
# clone repository
#
RUN git clone https://github.com/hibernate/hibernate-orm.git

#
# We'll use the hsqldb backend. 
#
RUN curl -o hsqldb-2.7.0.jar "http://www.hsqldb.org/download/hsqldb_270/hsqldb-2.7.0.jar"

COPY add-shadow.diff $SRC/
RUN cd ${SRC}/hibernate-orm && tr -d '\015' < $SRC/add-shadow.diff | git apply

COPY build.sh ${SRC}/
COPY *.java *.xml ${SRC}/
WORKDIR ${SRC}/hibernate-orm