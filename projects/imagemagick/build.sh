#!/bin/bash -eu
# Copyright 2017 Google Inc.  #
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

# Temporarily Add -D_GNU_SOURCE to CFLAGS to fix freetype's dependence on GNU
# extensions for dlsym to dynamically load harfbuzz. This feature
# should potentially be disabled instead of fixing the compilation. But that is
# not possible to do from the OSS-Fuzz repo :-)
# See https://github.com/google/oss-fuzz/pull/13325 for more details.
export CFLAGS="$CFLAGS -D_GNU_SOURCE"
. oss-fuzz/build.sh
