# Copyright 2016 Google Inc.
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

FROM gcr.io/oss-fuzz-base/base-runner
RUN apt-get update && apt-get install -y valgrind zip

# Installing GDB 12, re https://github.com/google/oss-fuzz/issues/7513.
RUN apt-get install -y build-essential libgmp-dev && \
    wget https://ftp.gnu.org/gnu/gdb/gdb-12.1.tar.xz && \
    tar -xf gdb-12.1.tar.xz && cd gdb-12.1 && ./configure &&  \
    make && make install && cd .. && rm -rf gdb-12.1* && \
    apt-get remove --purge -y build-essential libgmp-dev
