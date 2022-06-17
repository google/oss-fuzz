#!/bin/bash

# Copyright 2021 Google LLC
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


. multibuild/common_utils.sh

export CONFIGURE_BUILD_SOURCED=1
BUILD_PREFIX="${BUILD_PREFIX:-/usr/local}"
export CPPFLAGS="-I$BUILD_PREFIX/include $CPPFLAGS"
export LIBRARY_PATH="$BUILD_PREFIX/lib:$LIBRARY_PATH"
export PKG_CONFIG_PATH="$BUILD_PREFIX/lib/pkgconfig/:$PKG_CONFIG_PATH"

. multibuild/library_builders.sh
. config.sh

pre_build
