#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

# It is critical that this script, just as Samba's GitLab CI docker
# has LANG set to en_US.utf8
. /etc/default/locale
export LANG
export LC_ALL

# The real script is maintained in the Samba repo
exec lib/fuzzing/oss-fuzz/build_samba.sh
