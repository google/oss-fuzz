#!/bin/bash -eux
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

echo "Starting ruby installation"
RUBY_VERSION=3.3.1
RUBY_DEPS="binutils xz-utils libyaml-dev libffi-dev zlib1g-dev"
apt update && apt install -y $RUBY_DEPS
curl -O https://cache.ruby-lang.org/pub/ruby/3.3/ruby-$RUBY_VERSION.tar.gz
tar -xvf ruby-$RUBY_VERSION.tar.gz
cd ruby-$RUBY_VERSION
./configure --disable-install-doc --disable-install-rdoc --disable-install-capi
make -j$(nproc)
make install
cd ../

# Clean up the sources.
rm -rf ./ruby-$RUBY_VERSION ruby-$RUBY_VERSION.tar.gz

echo "Finished installing ruby"