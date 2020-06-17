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
RUN apt-get install -y --allow-downgrades --allow-remove-essential --allow-change-held-packages git make texinfo
RUN git clone --depth 1 https://github.com/tytso/e2fsprogs

COPY build.sh $SRC/
COPY ext2fs_combined_fuzzer.cc $SRC/
COPY ext2fs_open_fuzzer.cc $SRC/
COPY ext2fs_read_inode_bitmap_fuzzer.cc $SRC/
COPY ext2fs_read_block_bitmap_fuzzer.cc $SRC/
COPY ext2fs_check_directory_fuzzer.cc $SRC/
WORKDIR $SRC/e2fsprogs
