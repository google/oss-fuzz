#!/bin/bash -eu
# Copyright 2023 Google LLC
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

if ! test -e ${OUT}/jdk.tar.xz; then
	pushd ${SRC}/jdk
		bash configure --build x86_64-linux-gnu
		make images
		pushd ${SRC}/jdk/build/linux-x86_64-server-release/images
			tar cf ${OUT}/jdk.tar.xz jdk
		popd
	popd
fi