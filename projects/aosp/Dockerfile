# Copyright 2017 Google Inc.
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
RUN apt-get update && apt-get install -y curl

# Get AOSP's version of sqlite, and get the fuzz target from upstream.
# Once AOSP updates sqlite we'll be able to use the fuzz target from AOSP.
RUN git clone https://android.googlesource.com/platform/external/sqlite
RUN curl https://raw.githubusercontent.com/mackyle/sqlite/6bfffe7cfc8ff834e61f7d92a6509dbbca423b04/test/ossfuzz.c > sqlite_fuzz.c

# Copy the build file
COPY build.sh $SRC/
