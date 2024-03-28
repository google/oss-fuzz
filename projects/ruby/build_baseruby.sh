#!/bin/bash
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

# This script builds and installs the base ruby, which is used to bootstrap ruby from git sources.

set -euxo pipefail

# NOTE: You can find tarball URLs and SHA256 checksums at https://www.ruby-lang.org/en/downloads
ruby_tarball_url=https://cache.ruby-lang.org/pub/ruby/3.0/ruby-3.0.6.tar.gz
ruby_tarball_sha256=6e6cbd490030d7910c0ff20edefab4294dfcd1046f0f8f47f78b597987ac683e

# Download and verify the tarball
build_dir="$(mktemp -d -t build_baseruby.XXXXXX)"
curl -L -o "$build_dir/ruby.tar.gz" "$ruby_tarball_url"
echo "$ruby_tarball_sha256  $build_dir/ruby.tar.gz" | sha256sum -c -

# Extract the tarball
tar -C "$build_dir" -xzf "$build_dir/ruby.tar.gz" --strip-components=1

# Build and install the base ruby
cd "$build_dir"
./configure --disable-install-doc
make -j"$(nproc)"
make install
