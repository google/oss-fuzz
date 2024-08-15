#!/bin/bash -eu
# Copyright 2024 Google LLC. All rights reserved.
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

# Zephyr doesn't provide a "latest" link, so clone the source tree
# that produces the SDK (much smaller than the tarball itself, so
# minimal overhead) and find the latest version tag as a proxy.  Will
# likely break if the script is run in the moments between tagging a
# release and the tarball appearing on github, but the risk is low and
# it will recover with a retry.

git clone --filter=tree:0 https://github.com/zephyrproject-rtos/sdk-ng

VER=$(git -C sdk-ng tag -l 'v*' | sort -rV | head -1 | sed 's/v//')
URL="https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v$VER/zephyr-sdk-${VER}_linux-x86_64_minimal.tar.xz"

curl -L -o sdk.tar.xz "$URL"
tar xf sdk.tar.xz
rm sdk.tar.xz

zephyr-sdk-$VER/setup.sh -h
