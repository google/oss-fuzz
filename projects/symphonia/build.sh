#!/bin/bash -eu
# Copyright 2026 Google LLC
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

# The fuzz crate lives at symphonia/fuzz within the repository and declares
# its own cargo workspace, so build artifacts land under fuzz/target/.
cd $SRC/symphonia/symphonia

cargo fuzz build -O

cargo fuzz list | while read -r target; do
  cp "fuzz/target/x86_64-unknown-linux-gnu/release/$target" "$OUT/"

  # ClusterFuzz automatically uses $OUT/<target>.dict if present. Dictionaries
  # are keyed by format: the part of the target name after the first underscore
  # (decode_mpa -> mpa.dict, demux_mkv -> mkv.dict). Raw-sample decoders
  # (pcm, adpcm, alac, aac) have no syntax to tokenize and ship no dictionary.
  format="${target#*_}"
  if [ -f "$SRC/dicts/$format.dict" ]; then
    cp "$SRC/dicts/$format.dict" "$OUT/$target.dict"
  fi
done
