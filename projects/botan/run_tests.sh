#!/bin/bash -eux
# Copyright 2025 Google LLC.
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
##############################################################################

# Same rationale as build.sh: cap make jobs by available memory so the
# test build cannot be OOM-killed on memory-constrained hosts.
JOBS=$(nproc)
AVAIL_MB=$(free -m 2>/dev/null | awk '/^Mem:/{print $7}')
if [ -n "$AVAIL_MB" ]; then
   MEM_JOBS=$(( AVAIL_MB / 2560 ))
   if [ "$MEM_JOBS" -lt "$JOBS" ]; then
      JOBS=$MEM_JOBS
   fi
fi
if [ "$JOBS" -lt 1 ]; then
   JOBS=1
fi
make -j"${JOBS}" check
