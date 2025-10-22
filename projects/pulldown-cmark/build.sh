# Copyright 2024 Google LLC
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

# Note: This project creates Rust fuzz targets exclusively
cd $SRC/pulldown-cmark
CARGO_PROFILE_RELEASE_LTO=thin cargo fuzz build -O
cp target/x86_64-unknown-linux-gnu/release/commonmark_js $OUT/
cp target/x86_64-unknown-linux-gnu/release/parse $OUT/
