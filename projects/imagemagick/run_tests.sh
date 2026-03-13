#!/bin/sh -e
# Copyright 2025 Google LLC.
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

rgrep --files-with-matches '\-lheif' . \
  | xargs -r sed -i 's/-lheif/-lheif -lc++/'

# TODO: `make check` is preferred over `make check-TESTS`, as it is the public
# interface for comprehensive testing of ImageMagick.
make -j"$(nproc)" check-TESTS

# Undo patches.
rgrep --files-with-matches -- '-lheif -lc++' . \
  | xargs -r sed -i 's/-lheif -lc++/-lheif/'
