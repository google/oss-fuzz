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

apt-get update
apt-get install -y lsb-release software-properties-common gnupg2 binutils xz-utils libyaml-dev
gpg2 --keyserver keyserver.ubuntu.com --recv-keys 409B6B1796C275462A1703113804BB82D39DC0E3 7D2BAF1CF37B13E2069D6956105BD0E739499BDB
curl -sSL https://get.rvm.io | bash
. /etc/profile.d/rvm.sh

gem update --system 3.5.11

# Install ruzzy.
git clone https://github.com/trailofbits/ruzzy.git $SRC/ruzzy
cd $SRC/ruzzy

# The MAKE variable allows overwriting the make command at runtime. This forces
# the Ruby C extension to respect ENV variables when compiling, like CC, CFLAGS,
# etc.
MAKE="make --environment-overrides V=1" CC="clang" CXX="clang++" \
  LDSHARED="clang -shared" LDSHAREDXX="clang++ -shared" gem build

MAKE="make --environment-overrides V=1" \
CC="clang" \
CXX="clang++" \
LDSHARED="clang -shared" \
LDSHAREDXX="clang++ -shared" \
CXXFLAGS="-fPIC" \
CFLAGS="-fPIC" \
RUZZY_DEBUG=1 gem install --install-dir /install/ruzzy --development --verbose ruzzy-*.gem

rvm install ruby-3.3.1
