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
###############################################################################

# Remove tests that are not building with the fuzzing set up
rm unit/test-mesh-crypto.c
rm unit/test-midi.c
for unit_test in $(ls unit/test-*.c); do
  unit_name=$(basename ${unit_test})
  unit_name="${unit_name%.*}"
  echo ${unit_name}

  make unit/${unit_name}
  ./unit/${unit_name}
done
