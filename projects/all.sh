#!/bin/bash -eu
#
# Copyright 2016 Google Inc.
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

for project in projects/*; do
  if [[ -f $project ]]; then continue; fi
  echo "@ Building $project"
  docker build -t gcr.io/oss-fuzz/$project $project/

  # Execute command ($1) if any
  case ${1-} in
    "")
      ;;
    compile)
      docker run --rm -ti gcr.io/oss-fuzz/$project $@
      ;;
    *)
      echo $"Usage: $0 {|compile}"
      exit 1
  esac

done
