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

# use the github API to fetch the latest stable SDK with assets

RELEASES=$(curl -L  -H "Accept: application/vnd.github+json"  -H "X-GitHub-Api-Version: 2022-11-28"  https://api.github.com/repos/zephyrproject-rtos/sdk-ng/releases)
SDK=$(jq '[.[] | select(.prerelease == false) | {tag: .tag_name, assets: .assets[] | select(.name | contains("linux-x86_64_minimal.tar.xz"))}] | .[0]' <<< $RELEASES)

curl -L -o sdk.tar.xz $(jq -r '.assets.browser_download_url' <<< $SDK)
tar xf sdk.tar.xz
rm sdk.tar.xz

zephyr-sdk-$(jq -r ".tag" <<< $SDK | tr -d 'v')/setup.sh -h
