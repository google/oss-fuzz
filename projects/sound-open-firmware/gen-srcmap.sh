#!/bin/bash -eux
# Copyright 2023 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Copyright 2023 Google Inc.
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

FIRST_REC=yes

cd $SRC/sof

echo "{"
west list -f '{path} {url} {sha}' | sed 1d | while read dir url rev; do

    # Silly logic to suppress trailing comma
    if [ "$FIRST_REC" = yes ]; then
	FIRST_REC=no
    else
	echo ","
    fi

    echo    "  \"$SRC/sof/$dir\": {"
    echo    "    \"type\": \"git\","
    echo    "    \"url\": \"$url\","
    echo    "    \"rev\": \"$rev\""
    echo -n "  }"
done
echo
echo "}"
