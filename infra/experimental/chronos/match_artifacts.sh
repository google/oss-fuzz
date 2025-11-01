#!/usr/bin/bash -eux
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

CMP1=$1
CMP2=$2

for exec1 in $(find $CMP1/ -type f -executable); do
  base=$(basename $exec1)

  exec2=$CMP2/${base}
  if [ ! -f ${exec2} ]; then
    exit 1
  fi

  comparison=$(cmp --silent $exec1 $exec2; echo $?)
  if [[ $comparison -ne 0 ]]; then
    exit 1
  fi
done

exit 0
